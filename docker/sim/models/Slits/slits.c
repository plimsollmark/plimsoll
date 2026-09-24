// The double-slit plant of the control-design environments: Feynman's arrows as a
// plant. A monochromatic scalar wave (wavelength 1) leaves an aperture of NCELL
// cells, each PITCH wide and each carrying a phase plate the controller sets; every
// cell is modelled as SUB point sources, and the field at each of NSCR screen
// points a distance L away is the sum over all sources of e^{i k r} / sqrt(r), the
// two-dimensional Huygens sum. The intensity on the screen, normalised to its
// maximum, is what the controller sees, together with the target pattern it is
// asked to produce. The mask also carries a hidden phase defect per cell, set by
// the scenario, so a controller's own model of this plant is not this plant.
//
// A standalone module (no FMI framework): a field is not a handful of ODE states.
// It implements the shim contract directly, with the multi-input and output-
// Jacobian extensions the judge understands:
//
//   sim_init(p0, p1, p2, h, t_end)  p0 target family (1 one peak, 2 two peaks,
//                                    3 a flat top), p1 target position (screen
//                                    units), p2 defect amplitude (rad); h and t_end
//                                    only fix the tick count
//   sim_width()                     NSCR intensities then NSCR target values
//   sim_nin()                       NCELL: one commanded phase per cell
//   sim_step_n(u, out)              set the phases, recompute, write the state
//   sim_get(out), sim_free()
//   sim_nx()                        0: no ODE state, no state Jacobian
//   sim_jac_out(J)                  d(normalised intensity_j) / d(phase_n), NSCR x
//                                   NCELL row-major, exact from the closed form
//
// sin and cos come from wasi-libc inside the module, so the pattern does not
// depend on the host machine.
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#define NCELL 16
#define SUB 8
#define NSCR 64
#define PITCH 4.0
#define L 2000.0
#define SCREEN_HALF 200.0
#define TARGET_WIDTH 15.0

static double phase[NCELL];      // commanded phase per cell (rad)
static double defect[NCELL];     // hidden phase error per cell (rad)
static double baseR[NSCR][NCELL], baseI[NSCR][NCELL];  // each cell's field at phase 0
static double Er[NSCR], Ei[NSCR], I[NSCR], T[NSCR];
static double Imax;
static int32_t ticks, tick;

__attribute__((export_name("alloc")))
void *shim_alloc(size_t bytes) { return malloc(bytes); }

__attribute__((export_name("sim_width")))
int32_t sim_width(void) { return 2 * NSCR; }

__attribute__((export_name("sim_nin")))
int32_t sim_nin(void) { return NCELL; }

__attribute__((export_name("sim_nx")))
int32_t sim_nx(void) { return 0; }

static double screen_x(int j) { return (j - (NSCR - 1) / 2.0) * (2 * SCREEN_HALF / NSCR); }

static void compute(void) {
    Imax = 0;
    for (int j = 0; j < NSCR; j++) {
        double er = 0, ei = 0;
        for (int n = 0; n < NCELL; n++) {
            const double p = phase[n] + defect[n];
            const double c = cos(p), s = sin(p);
            er += baseR[j][n] * c - baseI[j][n] * s;
            ei += baseR[j][n] * s + baseI[j][n] * c;
        }
        Er[j] = er; Ei[j] = ei;
        I[j] = er * er + ei * ei;
        if (I[j] > Imax) Imax = I[j];
    }
    if (Imax <= 0) Imax = 1;
}

__attribute__((export_name("sim_init")))
int32_t sim_init(double p0, double p1, double p2, double h, double t_end) {
    if (h <= 0 || t_end <= 0) return -1;
    ticks = (int32_t)(t_end / h + 0.5);
    tick = 0;
    const double k = 2 * M_PI;
    for (int j = 0; j < NSCR; j++) {
        const double x = screen_x(j);
        for (int n = 0; n < NCELL; n++) {
            double er = 0, ei = 0;
            for (int s = 0; s < SUB; s++) {
                const double y = (n - (NCELL - 1) / 2.0) * PITCH + (s - (SUB - 1) / 2.0) * (PITCH / SUB);
                const double dx = x - y;
                const double r = sqrt(L * L + dx * dx);
                const double a = 1 / sqrt(r);
                er += a * cos(k * r);
                ei += a * sin(k * r);
            }
            baseR[j][n] = er; baseI[j][n] = ei;
        }
    }
    for (int n = 0; n < NCELL; n++) {
        phase[n] = 0;
        defect[n] = p2 * sin(2.399 * n + 0.7);
    }
    const int family = (int)p0;
    double tmax = 0;
    for (int j = 0; j < NSCR; j++) {
        const double x = screen_x(j);
        double t;
        if (family == 2) {
            const double a = (x - p1) / TARGET_WIDTH, b = (x + p1) / TARGET_WIDTH;
            t = exp(-a * a) + exp(-b * b);
        } else if (family == 3) {
            t = 0.5 * (tanh((x + p1) / TARGET_WIDTH) - tanh((x - p1) / TARGET_WIDTH));
        } else {
            const double a = (x - p1) / TARGET_WIDTH;
            t = exp(-a * a);
        }
        T[j] = t;
        if (t > tmax) tmax = t;
    }
    if (tmax <= 0) tmax = 1;
    for (int j = 0; j < NSCR; j++) T[j] /= tmax;
    compute();
    return 0;
}

__attribute__((export_name("sim_get")))
int32_t sim_get(double *out) {
    for (int j = 0; j < NSCR; j++) { out[j] = I[j] / Imax; out[NSCR + j] = T[j]; }
    return 0;
}

__attribute__((export_name("sim_step_n")))
int32_t sim_step_n(const double *u, double *out) {
    for (int n = 0; n < NCELL; n++) phase[n] = u[n];
    compute();
    sim_get(out);
    tick++;
    return tick < ticks ? 1 : 0;
}

// The scalar-input entry of the contract, kept so a single-input judge can still
// drive the plant: the one number sets every cell's phase.
__attribute__((export_name("sim_step")))
int32_t sim_step(double u, double *out) {
    double all[NCELL];
    for (int n = 0; n < NCELL; n++) all[n] = u;
    return sim_step_n(all, out);
}

// d(I_j / Imax) / d(phase_n). With E_j = sum_n E_jn and dE_jn/dphase_n = i E_jn,
// dI_j/dphase_n = 2 Re(conj(E_j) i E_jn) = 2 (Er_j * (-Ei_jn) ... ) written out
// below; the normalisation by the maximum adds the quotient term at the argmax.
__attribute__((export_name("sim_jac_out")))
int32_t sim_jac_out(double *J) {
    int jmax = 0;
    for (int j = 1; j < NSCR; j++) if (I[j] > I[jmax]) jmax = j;
    double dImax[NCELL];
    for (int n = 0; n < NCELL; n++) {
        const double p = phase[n] + defect[n];
        const double c = cos(p), s = sin(p);
        const double ejr = baseR[jmax][n] * c - baseI[jmax][n] * s;
        const double eji = baseR[jmax][n] * s + baseI[jmax][n] * c;
        dImax[n] = 2 * (Er[jmax] * (-eji) + Ei[jmax] * ejr);
    }
    for (int j = 0; j < NSCR; j++) {
        for (int n = 0; n < NCELL; n++) {
            const double p = phase[n] + defect[n];
            const double c = cos(p), s = sin(p);
            const double ejr = baseR[j][n] * c - baseI[j][n] * s;
            const double eji = baseR[j][n] * s + baseI[j][n] * c;
            const double dI = 2 * (Er[j] * (-eji) + Ei[j] * ejr);
            J[j * NCELL + n] = (dI - I[j] / Imax * dImax[n]) / Imax;
        }
    }
    return 0;
}

__attribute__((export_name("sim_free")))
void sim_free(void) {}
