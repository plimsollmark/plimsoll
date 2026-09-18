// Vendored from the plimsoll-sim repository at commit d3f9b28 (2026-09-18),
// unchanged below this header. That repository owns the worker source and its
// measurements; this copy is the one docker/sim.Dockerfile builds into
// plimsoll/sandbox-sim as /usr/local/bin/sim-worker.
// Datacenter-shaped worker on WasmEdge's C API: one module parsed and validated
// once, one executor per thread, a fresh store and instance per parameter set,
// AOT machine code. Two modes:
//
//   sweep: worker MODULE N threads t_end OUT p0min p0max p1 p2 [hold]
//     sweeps p0 over [p0min, p0max] with p1, p2 fixed and writes the same binary
//     layout as native_main.c (per run: int32 steps, then two float64 per step).
//     The apples-to-apples baseline; its output is what the checksums compare.
//
//   table: worker --table MODULE PARAMS OUT t_end h [max_bytes]
//     reads one parameter row per line from PARAMS (whitespace-separated
//     decimals, blank lines ignored), runs one fresh instance per row in this
//     thread, and writes OUT as a versioned record: a 20-byte header ("PLSM",
//     uint32 version 1, uint32 rows, uint32 width, uint32 params per row), then
//     per row an int32 status (steps completed when >= 0, a negative sim_run or
//     worker code otherwise) followed by status * width float64 outputs. The row
//     width is the module's own sim_run parameter count minus the four the
//     worker supplies (t_end, h, out, max_steps) and the output width is the
//     module's exported sim_width(), so the worker assumes no layout. A row that
//     fails is recorded and the table continues. With max_bytes > 0 the worker
//     refuses up front (exit 4) when the results could exceed that many bytes,
//     before running anything. Exit codes: 0 done, 1 module failed to load or
//     validate, 2 usage, 3 PARAMS malformed, 4 over the byte budget, 5 OUT
//     unwritable.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <wasmedge/wasmedge.h>

// Every instance's linear memory is capped at MAX_MEMORY_PAGES 64 KiB pages
// (16 MiB). A model that grows past it fails its own row (memory.grow refuses,
// malloc returns NULL, sim_run returns its negative code) instead of taking the
// worker and every other row down with the container's memory limit. The
// arithmetic: a row's result budget is at most 8 MiB (the table mode's
// max_bytes), so its out buffer fits with room for the model's own state; the
// wazero host in this repository caps at 64 pages and every model measured so
// far ran under that.
#define MAX_MEMORY_PAGES 256

static double now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec * 1e-9; }
static long rss_kb(void) { long pages = 0; FILE *f = fopen("/proc/self/statm", "r"); if (!f) return 0; if (fscanf(f, "%*ld %ld", &pages) != 1) pages = 0; fclose(f); return pages * (sysconf(_SC_PAGESIZE) / 1024); }

typedef struct { int N; double t_end, h, p0min, p0max, p1, p2; int32_t max_steps; } Sweep;
typedef struct { int32_t n; double *data; } Result;
typedef struct {
    int tid, nthreads; const Sweep *sw; const WasmEdge_ASTModuleContext *ast; const WasmEdge_ConfigureContext *conf;
    Result *results; double inst_time; long runs;
} Task;

// Instantiate from the shared AST, run one parameter set, tear down. Returns steps or negative.
static int32_t run_one(WasmEdge_ExecutorContext *exec, const WasmEdge_ASTModuleContext *ast, const Sweep *sw, double p0, double *out_data, double *inst_time) {
    double t0 = now();
    WasmEdge_StoreContext *store = WasmEdge_StoreCreate();
    WasmEdge_ModuleInstanceContext *wasi = WasmEdge_ModuleInstanceCreateWASI(NULL, 0, NULL, 0, NULL, 0);
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorRegisterImport(exec, store, wasi))) return -100;
    WasmEdge_ModuleInstanceContext *mod = NULL;
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorInstantiate(exec, &mod, store, ast))) return -101;
    WasmEdge_String s_init = WasmEdge_StringCreateByCString("_initialize");
    WasmEdge_FunctionInstanceContext *finit = WasmEdge_ModuleInstanceFindFunction(mod, s_init);
    if (finit && !WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, finit, NULL, 0, NULL, 0))) return -102;
    *inst_time += now() - t0;
    WasmEdge_String s_alloc = WasmEdge_StringCreateByCString("alloc");
    WasmEdge_String s_run = WasmEdge_StringCreateByCString("sim_run");
    WasmEdge_String s_mem = WasmEdge_StringCreateByCString("memory");
    WasmEdge_FunctionInstanceContext *falloc = WasmEdge_ModuleInstanceFindFunction(mod, s_alloc);
    WasmEdge_FunctionInstanceContext *frun = WasmEdge_ModuleInstanceFindFunction(mod, s_run);
    WasmEdge_Value a[1] = {WasmEdge_ValueGenI32(16 * sw->max_steps)}, ret[1];
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, falloc, a, 1, ret, 1))) return -103;
    int32_t ptr = WasmEdge_ValueGetI32(ret[0]);
    WasmEdge_Value p[7] = {WasmEdge_ValueGenF64(p0), WasmEdge_ValueGenF64(sw->p1), WasmEdge_ValueGenF64(sw->p2),
                           WasmEdge_ValueGenF64(sw->t_end), WasmEdge_ValueGenF64(sw->h), WasmEdge_ValueGenI32(ptr), WasmEdge_ValueGenI32(sw->max_steps)};
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, frun, p, 7, ret, 1))) return -104;
    int32_t n = WasmEdge_ValueGetI32(ret[0]);
    if (n > 0) {
        WasmEdge_MemoryInstanceContext *mem = WasmEdge_ModuleInstanceFindMemory(mod, s_mem);
        uint8_t *src = WasmEdge_MemoryInstanceGetPointer(mem, (uint64_t)ptr, (uint64_t)16 * n);
        if (!src) return -105;
        memcpy(out_data, src, (size_t)16 * n);
    }
    WasmEdge_StringDelete(s_init); WasmEdge_StringDelete(s_alloc); WasmEdge_StringDelete(s_run); WasmEdge_StringDelete(s_mem);
    WasmEdge_ModuleInstanceDelete(mod);
    WasmEdge_ModuleInstanceDelete(wasi);
    WasmEdge_StoreDelete(store);
    return n;
}

static void *thread_main(void *arg) {
    Task *t = arg;
    WasmEdge_ExecutorContext *exec = WasmEdge_ExecutorCreate(t->conf, NULL);
    for (int i = t->tid; i < t->sw->N; i += t->nthreads) {
        double p0 = t->sw->p0min + (t->sw->p0max - t->sw->p0min) * i / (double)(t->sw->N - 1);
        int32_t n = run_one(exec, t->ast, t->sw, p0, t->results[i].data, &t->inst_time);
        if (n < 0) { fprintf(stderr, "run %d failed: %d\n", i, n); exit(1); }
        t->results[i].n = n; t->runs++;
    }
    WasmEdge_ExecutorDelete(exec);
    return NULL;
}

// ---- table mode ---------------------------------------------------------------

typedef struct { int32_t nparams, width; } ModuleShape;

// Instantiate once to read the module's contract: sim_run's parameter count and
// sim_width(). Returns 0 or a negative code.
static int module_shape(WasmEdge_ExecutorContext *exec, const WasmEdge_ASTModuleContext *ast, ModuleShape *shape) {
    WasmEdge_StoreContext *store = WasmEdge_StoreCreate();
    WasmEdge_ModuleInstanceContext *wasi = WasmEdge_ModuleInstanceCreateWASI(NULL, 0, NULL, 0, NULL, 0);
    WasmEdge_ModuleInstanceContext *mod = NULL;
    int rc = 0;
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorRegisterImport(exec, store, wasi))) { rc = -100; goto done; }
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorInstantiate(exec, &mod, store, ast))) { rc = -101; goto done; }
    WasmEdge_String s_init = WasmEdge_StringCreateByCString("_initialize");
    WasmEdge_String s_run = WasmEdge_StringCreateByCString("sim_run");
    WasmEdge_String s_width = WasmEdge_StringCreateByCString("sim_width");
    WasmEdge_FunctionInstanceContext *finit = WasmEdge_ModuleInstanceFindFunction(mod, s_init);
    if (finit && !WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, finit, NULL, 0, NULL, 0))) rc = -102;
    WasmEdge_FunctionInstanceContext *frun = WasmEdge_ModuleInstanceFindFunction(mod, s_run);
    WasmEdge_FunctionInstanceContext *fwidth = WasmEdge_ModuleInstanceFindFunction(mod, s_width);
    if (rc == 0 && (!frun || !fwidth)) rc = -106;
    if (rc == 0) {
        const WasmEdge_FunctionTypeContext *ft = WasmEdge_FunctionInstanceGetFunctionType(frun);
        uint32_t np = WasmEdge_FunctionTypeGetParametersLength(ft);
        WasmEdge_Value ret[1];
        if (np < 5 || WasmEdge_FunctionTypeGetReturnsLength(ft) != 1) rc = -107;
        else if (!WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, fwidth, NULL, 0, ret, 1))) rc = -108;
        else { shape->nparams = (int32_t)np - 4; shape->width = WasmEdge_ValueGetI32(ret[0]); if (shape->width < 1) rc = -109; }
    }
    WasmEdge_StringDelete(s_init); WasmEdge_StringDelete(s_run); WasmEdge_StringDelete(s_width);
done:
    if (mod) WasmEdge_ModuleInstanceDelete(mod);
    WasmEdge_ModuleInstanceDelete(wasi);
    WasmEdge_StoreDelete(store);
    return rc;
}

// One fresh instance for one parameter row. Returns steps completed (>= 0) or a
// negative code; out receives width doubles per step.
static int32_t run_row(WasmEdge_ExecutorContext *exec, const WasmEdge_ASTModuleContext *ast, const ModuleShape *shape,
                       const double *row, double t_end, double h, int32_t max_steps, double *out) {
    WasmEdge_StoreContext *store = WasmEdge_StoreCreate();
    WasmEdge_ModuleInstanceContext *wasi = WasmEdge_ModuleInstanceCreateWASI(NULL, 0, NULL, 0, NULL, 0);
    WasmEdge_ModuleInstanceContext *mod = NULL;
    int32_t n = 0;
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorRegisterImport(exec, store, wasi))) { n = -100; goto done; }
    if (!WasmEdge_ResultOK(WasmEdge_ExecutorInstantiate(exec, &mod, store, ast))) { n = -101; goto done; }
    WasmEdge_String s_init = WasmEdge_StringCreateByCString("_initialize");
    WasmEdge_String s_alloc = WasmEdge_StringCreateByCString("alloc");
    WasmEdge_String s_run = WasmEdge_StringCreateByCString("sim_run");
    WasmEdge_String s_mem = WasmEdge_StringCreateByCString("memory");
    WasmEdge_FunctionInstanceContext *finit = WasmEdge_ModuleInstanceFindFunction(mod, s_init);
    if (finit && !WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, finit, NULL, 0, NULL, 0))) n = -102;
    if (n == 0) {
        WasmEdge_FunctionInstanceContext *falloc = WasmEdge_ModuleInstanceFindFunction(mod, s_alloc);
        WasmEdge_FunctionInstanceContext *frun = WasmEdge_ModuleInstanceFindFunction(mod, s_run);
        size_t bytes = (size_t)8 * shape->width * max_steps;
        WasmEdge_Value a[1] = {WasmEdge_ValueGenI32((int32_t)bytes)}, ret[1];
        if (!falloc || !frun || !WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, falloc, a, 1, ret, 1))) n = -103;
        else {
            int32_t ptr = WasmEdge_ValueGetI32(ret[0]);
            WasmEdge_Value *p = malloc(sizeof(WasmEdge_Value) * (shape->nparams + 4));
            for (int k = 0; k < shape->nparams; k++) p[k] = WasmEdge_ValueGenF64(row[k]);
            p[shape->nparams] = WasmEdge_ValueGenF64(t_end);
            p[shape->nparams + 1] = WasmEdge_ValueGenF64(h);
            p[shape->nparams + 2] = WasmEdge_ValueGenI32(ptr);
            p[shape->nparams + 3] = WasmEdge_ValueGenI32(max_steps);
            if (!WasmEdge_ResultOK(WasmEdge_ExecutorInvoke(exec, frun, p, (uint32_t)(shape->nparams + 4), ret, 1))) n = -104;
            else n = WasmEdge_ValueGetI32(ret[0]);
            free(p);
            if (n > 0) {
                WasmEdge_MemoryInstanceContext *mem = WasmEdge_ModuleInstanceFindMemory(mod, s_mem);
                uint8_t *src = mem ? WasmEdge_MemoryInstanceGetPointer(mem, (uint64_t)ptr, (uint64_t)8 * shape->width * n) : NULL;
                if (!src) n = -105; else memcpy(out, src, (size_t)8 * shape->width * n);
            }
        }
    }
    WasmEdge_StringDelete(s_init); WasmEdge_StringDelete(s_alloc); WasmEdge_StringDelete(s_run); WasmEdge_StringDelete(s_mem);
done:
    if (mod) WasmEdge_ModuleInstanceDelete(mod);
    WasmEdge_ModuleInstanceDelete(wasi);
    WasmEdge_StoreDelete(store);
    return n;
}

// Parse PARAMS: one row per non-blank line, nparams decimals each, strtod with
// full consumption. Returns the row count or -1 after a message naming the line.
static long read_table(const char *path, int32_t nparams, double **rows_out) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open params file\n"); return -1; }
    double *rows = NULL; long n = 0, cap = 0; char line[65536]; long lineno = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n') { fprintf(stderr, "params line %ld is too long\n", lineno); free(rows); fclose(f); return -1; }
        char *p = line; int k = 0;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\n' || *p == '\0') continue;
        if (n == cap) { cap = cap ? cap * 2 : 256; rows = realloc(rows, sizeof(double) * cap * nparams); if (!rows) { fprintf(stderr, "out of memory\n"); fclose(f); return -1; } }
        while (*p && *p != '\n') {
            char *end; double v = strtod(p, &end);
            if (end == p || k >= nparams) { fprintf(stderr, "params line %ld: expected %d values\n", lineno, nparams); free(rows); fclose(f); return -1; }
            rows[n * nparams + k++] = v; p = end;
            while (*p == ' ' || *p == '\t') p++;
        }
        if (k != nparams) { fprintf(stderr, "params line %ld: expected %d values, got %d\n", lineno, nparams, k); free(rows); fclose(f); return -1; }
        n++;
    }
    fclose(f);
    *rows_out = rows;
    return n;
}

static int run_table(const char *path, const char *params_path, const char *outp, double t_end, double h, long max_bytes) {
    if (!(t_end > 0) || !(h > 0)) { fprintf(stderr, "t_end and h must be positive\n"); return 2; }
    WasmEdge_ConfigureContext *conf = WasmEdge_ConfigureCreate();
    WasmEdge_ConfigureAddHostRegistration(conf, WasmEdge_HostRegistration_Wasi);
    WasmEdge_ConfigureSetRunMode(conf, WasmEdge_RunMode_AOT);
    WasmEdge_ConfigureSetMaxMemoryPage(conf, MAX_MEMORY_PAGES);
    double t0 = now();
    WasmEdge_LoaderContext *loader = WasmEdge_LoaderCreate(conf);
    WasmEdge_ASTModuleContext *ast = NULL;
    if (!WasmEdge_ResultOK(WasmEdge_LoaderParseFromFile(loader, &ast, path))) { fprintf(stderr, "load failed\n"); return 1; }
    WasmEdge_ValidatorContext *val = WasmEdge_ValidatorCreate(conf);
    if (!WasmEdge_ResultOK(WasmEdge_ValidatorValidate(val, ast))) { fprintf(stderr, "validate failed\n"); return 1; }
    WasmEdge_ExecutorContext *exec = WasmEdge_ExecutorCreate(conf, NULL);
    ModuleShape shape;
    int rc = module_shape(exec, ast, &shape);
    if (rc != 0) { fprintf(stderr, "module does not export the sim_run/sim_width contract: %d\n", rc); return 1; }
    double load_time = now() - t0;

    double *rows = NULL;
    long n = read_table(params_path, shape.nparams, &rows);
    if (n < 0) return 3;
    if (n == 0) { fprintf(stderr, "params file has no rows\n"); return 3; }
    int32_t max_steps = (int32_t)(t_end / h) + 2;
    long worst = 20 + n * (4 + 8L * shape.width * max_steps);
    if (max_bytes > 0 && worst > max_bytes) {
        fprintf(stderr, "results could reach %ld bytes for %ld rows of up to %d steps, over the %ld byte budget; send fewer rows or a shorter horizon\n", worst, n, max_steps, max_bytes);
        return 4;
    }
    FILE *f = fopen(outp, "wb");
    if (!f) { fprintf(stderr, "cannot open output file\n"); return 5; }
    uint32_t hdr[4] = {1, (uint32_t)n, (uint32_t)shape.width, (uint32_t)shape.nparams};
    if (fwrite("PLSM", 1, 4, f) != 4 || fwrite(hdr, sizeof(uint32_t), 4, f) != 4) { fprintf(stderr, "output write failed\n"); return 5; }
    double *out = malloc(sizeof(double) * shape.width * max_steps);
    double ts = now(); long ok = 0, failed = 0, steps = 0;
    for (long i = 0; i < n; i++) {
        int32_t st = run_row(exec, ast, &shape, rows + i * shape.nparams, t_end, h, max_steps, out);
        if (st >= 0) { ok++; steps += st; } else failed++;
        if (fwrite(&st, sizeof st, 1, f) != 1) { fprintf(stderr, "output write failed\n"); return 5; }
        if (st > 0 && fwrite(out, sizeof(double), (size_t)shape.width * st, f) != (size_t)shape.width * st) { fprintf(stderr, "output write failed\n"); return 5; }
    }
    double wall = now() - ts;
    if (fclose(f) != 0) { fprintf(stderr, "output write failed\n"); return 5; }
    printf("wasmedge-worker(table) %s rows=%ld params=%d width=%d ok=%ld failed=%ld load+validate=%.1fms wall=%.4fs steps=%ld\n",
           path, n, shape.nparams, shape.width, ok, failed, load_time * 1e3, wall, steps);
    free(out); free(rows);
    WasmEdge_ExecutorDelete(exec); WasmEdge_ValidatorDelete(val); WasmEdge_LoaderDelete(loader); WasmEdge_ASTModuleDelete(ast); WasmEdge_ConfigureDelete(conf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--table") == 0) {
        if (argc < 7) { fprintf(stderr, "usage: worker --table MODULE PARAMS OUT t_end h [max_bytes]\n"); return 2; }
        return run_table(argv[2], argv[3], argv[4], atof(argv[5]), atof(argv[6]), argc > 7 ? atol(argv[7]) : 0);
    }
    if (argc < 10) { fprintf(stderr, "usage: worker MODULE N threads t_end out p0min p0max p1 p2 [hold]\n"); return 2; }
    const char *path = argv[1]; Sweep sw = {atoi(argv[2]), atof(argv[4]), 0.01, atof(argv[6]), atof(argv[7]), atof(argv[8]), atof(argv[9]), 0};
    int nthreads = atoi(argv[3]); const char *outp = argv[5]; int hold = argc > 10 ? atoi(argv[10]) : 0;
    sw.max_steps = (int32_t)(sw.t_end / sw.h) + 2;
    WasmEdge_ConfigureContext *conf = WasmEdge_ConfigureCreate();
    WasmEdge_ConfigureAddHostRegistration(conf, WasmEdge_HostRegistration_Wasi);
    WasmEdge_ConfigureSetRunMode(conf, WasmEdge_RunMode_AOT);
    WasmEdge_ConfigureSetMaxMemoryPage(conf, MAX_MEMORY_PAGES);
    double t0 = now();
    WasmEdge_LoaderContext *loader = WasmEdge_LoaderCreate(conf);
    WasmEdge_ASTModuleContext *ast = NULL;
    if (!WasmEdge_ResultOK(WasmEdge_LoaderParseFromFile(loader, &ast, path))) { fprintf(stderr, "load failed\n"); return 1; }
    WasmEdge_ValidatorContext *val = WasmEdge_ValidatorCreate(conf);
    if (!WasmEdge_ResultOK(WasmEdge_ValidatorValidate(val, ast))) { fprintf(stderr, "validate failed\n"); return 1; }
    double load_time = now() - t0;

    if (hold > 0) { // memory per held instance: instantiate `hold` instances and keep them
        WasmEdge_ExecutorContext *exec = WasmEdge_ExecutorCreate(conf, NULL);
        long before = rss_kb();
        WasmEdge_StoreContext **stores = malloc(sizeof(*stores) * hold);
        WasmEdge_ModuleInstanceContext **mods = malloc(sizeof(*mods) * hold), **wasis = malloc(sizeof(*wasis) * hold);
        double th = now();
        for (int i = 0; i < hold; i++) {
            stores[i] = WasmEdge_StoreCreate(); wasis[i] = WasmEdge_ModuleInstanceCreateWASI(NULL, 0, NULL, 0, NULL, 0);
            WasmEdge_ExecutorRegisterImport(exec, stores[i], wasis[i]);
            if (!WasmEdge_ResultOK(WasmEdge_ExecutorInstantiate(exec, &mods[i], stores[i], ast))) { fprintf(stderr, "hold instantiate failed at %d\n", i); return 1; }
        }
        double dth = now() - th; long after = rss_kb();
        printf("hold %d instances: %.1f us each to instantiate, RSS +%ld KiB = %.1f KiB per instance\n", hold, dth * 1e6 / hold, after - before, (after - before) / (double)hold);
        return 0;
    }

    Result *results = calloc(sw.N, sizeof(Result));
    for (int i = 0; i < sw.N; i++) results[i].data = malloc(sizeof(double) * 2 * sw.max_steps);
    Task *tasks = calloc(nthreads, sizeof(Task)); pthread_t *th = calloc(nthreads, sizeof(pthread_t));
    double ts = now();
    for (int k = 0; k < nthreads; k++) { tasks[k] = (Task){k, nthreads, &sw, ast, conf, results, 0, 0}; pthread_create(&th[k], NULL, thread_main, &tasks[k]); }
    double inst_total = 0; long runs = 0;
    for (int k = 0; k < nthreads; k++) { pthread_join(th[k], NULL); inst_total += tasks[k].inst_time; runs += tasks[k].runs; }
    double wall = now() - ts;
    long steps = 0; FILE *f = fopen(outp, "wb");
    for (int i = 0; i < sw.N; i++) { steps += results[i].n; fwrite(&results[i].n, sizeof(int32_t), 1, f); fwrite(results[i].data, sizeof(double), 2 * (size_t)results[i].n, f); }
    fclose(f);
    printf("wasmedge-worker(aot) %s N=%d threads=%d load+validate=%.1fms instantiate_avg=%.1fus wall=%.4fs steps=%ld ns_per_step_wall=%.1f steps_per_second=%.0f runs_per_second=%.0f\n",
           path, sw.N, nthreads, load_time * 1e3, inst_total * 1e6 / runs, wall, steps, wall * 1e9 / steps, steps / wall, runs / wall);
    WasmEdge_ValidatorDelete(val); WasmEdge_LoaderDelete(loader); WasmEdge_ASTModuleDelete(ast); WasmEdge_ConfigureDelete(conf);
    return 0;
}
