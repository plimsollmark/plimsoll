// Incompressible, quasi-steady plumbing with finite water volumes. Every pipe
// uses the same conservative mixed-cell transport rule. Units: litres, seconds,
// degrees Celsius and bar. Linear hydraulic resistances are an explicit model
// approximation; this is not a calibration to a particular valve or shower.
#ifndef SHOWER_PHYSICS_H
#define SHOWER_PHYSICS_H
#include <math.h>
#include <stddef.h>

#define SHOWER_CELLS 16
#define SHOWER_DT 0.005
#define SHOWER_HOT 2
#define SHOWER_COLD (SHOWER_HOT + SHOWER_CELLS)
#define SHOWER_OUT (SHOWER_COLD + SHOWER_CELLS)
#define SHOWER_VOLUME (SHOWER_OUT + SHOWER_CELLS)
#define SHOWER_HOT_VOLUME (SHOWER_VOLUME + 1)
#define SHOWER_NX (SHOWER_HOT_VOLUME + 1)

typedef struct {
    double hot_volume, hot_temperature, flush_time;
    double cold_volume, outlet_volume, cold_temperature, ambient_temperature;
    double cooling_time, hot_pressure, cold_pressure, flush_pressure_fraction;
    double flush_length;
} ShowerParameters;

typedef struct { double hot, cold, outlet, pressure, mixed_temperature; } ShowerFlow;

static double shower_opening(double a) {
    // Snap numerical residue at a closed seat to zero. Commands otherwise have
    // a finite travel speed: fully open to fully shut takes half a second.
    if (a < 1e-12) return 0;
    return a > 1 ? 1 : a;
}

static ShowerFlow shower_flow(double hot, double cold, double ph, double pc) {
    const double gh = 0.1 * shower_opening(hot);
    const double gc = 0.1 * shower_opening(cold);
    const double go = 0.08;
    double pm = (gh * ph + gc * pc) / (gh + gc + go);
    // Non-return valves prevent reverse flow into a low-pressure supply.
    if (pm > pc) pm = gh * ph / (gh + go);
    else if (pm > ph) pm = gc * pc / (gc + go);
    double qh = gh * (ph - pm), qc = gc * (pc - pm);
    if (qh < 0) qh = 0;
    if (qc < 0) qc = 0;
    return (ShowerFlow){qh, qc, qh + qc, pm, 0};
}

static void shower_pipe(const double *x, double *dx, double inlet, double flow,
                        double volume, double ambient, double cooling_time) {
    const double transport = flow * SHOWER_CELLS / volume;
    for (size_t i = 0; i < SHOWER_CELLS; i++) {
        const double upstream = i ? x[i - 1] : inlet;
        dx[i] = transport * (upstream - x[i]);
        if (cooling_time > 0) dx[i] += (ambient - x[i]) / cooling_time;
    }
}

static ShowerFlow shower_rhs(double t, const ShowerParameters *p,
                            const double *x, const double *u, double *dx) {
    const int flushing = t >= p->flush_time && t < p->flush_time + p->flush_length;
    ShowerFlow f = shower_flow(x[0], x[1], p->hot_pressure,
                              p->cold_pressure * (flushing ? p->flush_pressure_fraction : 1));
    for (size_t i = 0; i < 2; i++) {
        double d = (u[i] - x[i]) / SHOWER_DT;
        dx[i] = d > 2 ? 2 : d < -2 ? -2 : d;
    }
    const double th = x[SHOWER_HOT + SHOWER_CELLS - 1];
    const double tc = x[SHOWER_COLD + SHOWER_CELLS - 1];
    // At no flow, this value is unused by transport. Retain the outlet's inlet
    // cell temperature instead of inventing a delivered temperature.
    f.mixed_temperature = f.outlet > 0 ? (f.hot * th + f.cold * tc) / f.outlet : x[SHOWER_OUT];
    shower_pipe(x + SHOWER_HOT, dx + SHOWER_HOT, p->hot_temperature, f.hot,
                p->hot_volume, p->ambient_temperature, p->cooling_time);
    shower_pipe(x + SHOWER_COLD, dx + SHOWER_COLD, p->cold_temperature, f.cold,
                p->cold_volume, p->ambient_temperature, p->cooling_time);
    shower_pipe(x + SHOWER_OUT, dx + SHOWER_OUT, f.mixed_temperature, f.outlet,
                p->outlet_volume, p->ambient_temperature, p->cooling_time);
    dx[SHOWER_VOLUME] = f.outlet;
    dx[SHOWER_HOT_VOLUME] = f.hot;
    return f;
}
#endif
