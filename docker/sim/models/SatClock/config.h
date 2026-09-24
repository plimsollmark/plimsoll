// The relativistic clock-steering plant of the control-design environments, in
// the Reference FMU style, stepped by sim/shim_env.c with the value references in
// plant.h. General relativity in the pocket: the clock on a navigation satellite.
//
// A satellite clock in a 12-hour orbit runs fast relative to a ground clock: the
// weaker gravitational potential gains about 45.7 microseconds a day, its speed
// loses about 7.2, net about 38.6 microseconds a day fast, the number every
// receiver corrects for. An eccentric orbit adds a periodic term with amplitude
// 2 sqrt(GM a) e / c^2 (about 46 nanoseconds at e = 0.02) at the orbital period.
// The oscillator has its own unknown constant frequency offset. The ground
// station measures the clock error against system time, but the measurement
// reaches the controller late: a transport delay of D seconds, modelled as six
// lags in series like the shower's pipe.
//
// State: the clock error x (onboard reading minus system time, seconds) and the
// six delay-line stages. Rate of x: the relativistic rate (constant plus the
// eccentricity term), the oscillator offset, and the commanded fractional
// frequency correction u (dimensionless, clamped to plus or minus 1e-8).
#ifndef config_h
#define config_h

#define MODEL_IDENTIFIER SatClock
#define INSTANTIATION_TOKEN "{C3F8A1D5-6E2B-4C7A-9D0F-1B4E8A6C2F93}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 7

#define SET_FLOAT64

// Ten forward Euler substeps per 30 s tick; the fastest lag is D/6 with D >= 120 s.
#define FIXED_SOLVER_STEP 3
#define DEFAULT_STOP_TIME 86400

typedef enum {
    vr_time,
    vr_x, vr_der_x,
    vr_d1, vr_der_d1, vr_d2, vr_der_d2, vr_d3, vr_der_d3,
    vr_d4, vr_der_d4, vr_d5, vr_der_d5, vr_d6, vr_der_d6,
    vr_u,
    vr_e, vr_y0, vr_D,
    vr_rate_gr, vr_ecc_amp, vr_omega, vr_u_max
} ValueReference;

typedef struct {

    double x;         // clock error (s), onboard minus system time
    double der_x;
    double d1, der_d1;   // delay line: the measurement travelling to the controller
    double d2, der_d2;
    double d3, der_d3;
    double d4, der_d4;
    double d5, der_d5;
    double d6, der_d6;
    double u;         // INPUT: commanded fractional frequency correction
    double e;         // PARAMETER p0: orbital eccentricity
    double y0;        // PARAMETER p1: oscillator fractional frequency offset
    double D;         // PARAMETER p2: measurement delay (s)
    double rate_gr;   // net relativistic rate, s/s (38.6 us/day)
    double ecc_amp;   // eccentricity time-offset amplitude per unit e (s), 2 sqrt(GM a) / c^2
    double omega;     // orbital angular frequency (rad/s), 12 h period
    double u_max;     // correction limit

} ModelData;

#endif /* config_h */
