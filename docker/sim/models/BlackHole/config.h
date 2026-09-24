// The black-hole station-keeping plant of the control-design environments, in
// the Reference FMU style, stepped by sim/shim_env.c with the value references in
// plant.h. General relativity: a probe on a geodesic of the Schwarzschild metric,
// with two small thrusters.
//
// Units G = c = M = 1: distances in gravitational radii, times in the light-
// crossing time of one. The horizon is at r = 2, the photon sphere at 3, and the
// innermost stable circular orbit at 6: below it a circular orbit is an unstable
// equilibrium, which is what makes holding a probe there a control problem, the
// relativistic twin of balancing the cart-pole.
//
// The independent variable is the probe's proper time tau. Without thrust the
// equations are the exact Schwarzschild geodesic equations in the form
//   d2r/dtau2 = -1/r^2 + L^2/r^3 - 3 L^2/r^4,   dphi/dtau = L/r^2,
//   dt/dtau = E / (1 - 2/r),  E^2 = (dr/dtau)^2 + (1 - 2/r)(1 + L^2/r^2),
// with L the specific angular momentum and t the far-away observer's time.
// Thrust enters as proper-acceleration components in the probe's radial and
// azimuthal directions: a_r adds to d2r/dtau2, a_phi changes L at r a_phi. That
// is exact for the geodesic part and first order in the thrust for the forcing,
// which is the regime of a small-thrust station-keeping problem. Fuel is the
// integral of |a_r| + |a_phi| over proper time (a delta-v in units of c).
#ifndef config_h
#define config_h

#define MODEL_IDENTIFIER BlackHole
#define INSTANTIATION_TOKEN "{5E1A7C93-2B4D-4F6E-8A0B-9C3D1E5F7A2B}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 6

#define SET_FLOAT64

// One thousand forward Euler substeps per tick of one time unit. The Reference
// FMU framework integrates with explicit Euler, which drifts on an orbit: at a
// substep of 0.01 the perihelion advance measured at r = 50 changed from one
// orbit to the next; at 0.001 it is the same orbit after orbit (0.4147 rad at
// a = 51, e = 0.146) and agrees to under one percent with the second-order
// Schwarzschild result 6 pi M / p times (1 + (M / p)(18 + e^2) / 4), p = a (1 - e^2).
// The familiar first-order 6 pi M / p is ten percent low there, which is the
// expansion, not the plant.
#define FIXED_SOLVER_STEP 1e-3
#define DEFAULT_STOP_TIME 600

typedef enum {
    vr_time,
    vr_r, vr_der_r,
    vr_v, vr_der_v,
    vr_phi, vr_der_phi,
    vr_L, vr_der_L,
    vr_t, vr_der_t,
    vr_fuel, vr_der_fuel,
    vr_a_r, vr_a_phi,
    vr_r_target, vr_v0, vr_a_max,
    vr_omega
} ValueReference;

typedef struct {

    double r;        // radius (gravitational radii)
    double der_r;
    double v;        // dr/dtau
    double der_v;
    double phi;      // azimuth (rad)
    double der_phi;
    double L;        // specific angular momentum
    double der_L;
    double t;        // far-away observer's time
    double der_t;
    double fuel;     // delta-v spent (units of c)
    double der_fuel;
    double a_r;      // INPUT 0: radial proper acceleration
    double a_phi;    // INPUT 1: azimuthal proper acceleration
    double r_target; // PARAMETER p0: the radius to hold; also the initial radius
    double v0;       // PARAMETER p1: initial radial velocity (the kick)
    double a_max;    // PARAMETER p2: thrust limit per component
    double omega;    // dphi/dtau, derived, observed

} ModelData;

#endif /* config_h */
