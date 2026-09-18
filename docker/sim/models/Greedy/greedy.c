// Vendored from the plimsoll-sim repository at commit d3f9b28 (2026-09-18),
// unchanged below this header. A test fixture, not an FMU: it proves the worker's
// per-instance memory cap (sandbox/docker_sim_test.go).
// Greedy is a test fixture, not an FMU: a module with the worker's sim contract
// (alloc, sim_width, sim_run) whose only behaviour is to allocate p0 MiB, one
// chained 1 MiB chunk at a time. It exists to prove the worker's per-instance
// memory cap: a row that asks for more than the cap fails on its own (sim_run
// returns -7 when malloc refuses) while the rows around it complete, and the
// worker never sees the container's memory limit. The chunks are chained and the
// chain is walked at the end, so the compiler cannot delete the allocations as
// unobserved (clang at -O2 will remove a malloc whose result is never read).
#include <stdlib.h>
#include <stdint.h>

__attribute__((export_name("alloc")))
void *shim_alloc(size_t bytes) { return malloc(bytes); }

__attribute__((export_name("sim_width")))
int32_t sim_width(void) { return 1; }

__attribute__((export_name("sim_run")))
int32_t sim_run(double p0, double p1, double p2, double t_end, double h, double *out, int32_t max_steps) {
    (void)p2; (void)t_end; (void)h;
    if (max_steps < 1) return -1;
    long mib = (long)p0;
    char *volatile head = NULL;
    for (long i = 0; i < mib; i++) {
        char *chunk = malloc(1 << 20);
        if (!chunk) return -7;
        *(char **)chunk = head; /* chain it */
        chunk[(1 << 20) - 1] = (char)i; /* touch the last page too */
        head = chunk;
    }
    long walked = 0;
    for (char *c = head; c; c = *(char **)c) walked++;
    out[0] = (walked == mib) ? p1 : -1;
    return 1;
}
