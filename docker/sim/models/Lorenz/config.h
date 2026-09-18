// Vendored from the plimsoll-sim repository at commit 0be8574 (2026-09-18),
// unchanged below this header. The Lorenz model of our own, in the Reference FMU style
// (models/Lorenz there); built against the Reference FMUs' fmi3Functions.c and
// cosimulation.c like their own models.
#ifndef config_h
#define config_h

// define class name and unique id
#define MODEL_IDENTIFIER Lorenz
#define INSTANTIATION_TOKEN "{04D78D0D-C43D-4398-9272-AC49A652338F}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 3

#define SET_FLOAT64

#define GET_PARTIAL_DERIVATIVE

// Ten forward Euler steps per 10 ms communication step: the Reference FMUs
// integrate with forward Euler at FIXED_SOLVER_STEP, and 1e-2 is too coarse for
// the Lorenz vector field (its local rates reach 100 per time unit near the
// attractor's wings).
#define FIXED_SOLVER_STEP 1e-3
#define DEFAULT_STOP_TIME 60

typedef enum {
    vr_time, vr_x, vr_der_x, vr_y, vr_der_y, vr_z, vr_der_z, vr_sigma, vr_rho, vr_beta
} ValueReference;

typedef struct {

    double x;
    double der_x;
    double y;
    double der_y;
    double z;
    double der_z;
    double sigma;
    double rho;
    double beta;

} ModelData;

#endif /* config_h */
