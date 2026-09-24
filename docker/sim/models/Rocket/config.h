// The twin-paradox rocket of the control-design environments, in the Reference
// FMU style, stepped by sim/shim_env.c with the value references in plant.h.
// Special relativity: forward time travel on a fuel budget.
//
// Units c = 1, time in years, distance in light-years, so a proper acceleration
// of 1 is one light-year per year squared, about 0.97 g. The independent
// variable is the ship's own proper time tau. With rapidity eta the exact
// relativistic rocket equations are
//   d eta / dtau = a,   dx/dtau = sinh eta,   dt/dtau = cosh eta,
// where a is the proper acceleration the controller commands (clamped to a_max),
// x the position in Earth's frame and t Earth's clock. Fuel is the integral of
// |a| over proper time, which for an ideal rocket is the rapidity spent (the
// relativistic delta-v).
//
// The controller's job: leave, turn around, come home so that Earth's clock
// reads the ordered date on arrival. For a symmetric four-phase trip at
// acceleration a with phases of proper time tau1 each, Earth time is
// 4 sinh(a tau1) / a while the ship ages 4 tau1: at a = 1 and an ordered 40
// Earth years, the ship ages 12.
#ifndef config_h
#define config_h

#define MODEL_IDENTIFIER Rocket
#define INSTANTIATION_TOKEN "{A7D2E4B6-8C1F-4E3A-9B5D-6F0C2A8E4D71}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 4

#define SET_FLOAT64

// Ten forward Euler substeps per 0.05 year tick.
#define FIXED_SOLVER_STEP 5e-3
#define DEFAULT_STOP_TIME 30

typedef enum {
    vr_time,
    vr_eta, vr_der_eta,
    vr_x, vr_der_x,
    vr_t, vr_der_t,
    vr_fuel, vr_der_fuel,
    vr_a,
    vr_T_target, vr_fuel_budget, vr_a_max,
    vr_beta
} ValueReference;

typedef struct {

    double eta;         // rapidity
    double der_eta;
    double x;           // position in Earth's frame (light-years)
    double der_x;
    double t;           // Earth's clock (years)
    double der_t;
    double fuel;        // rapidity spent
    double der_fuel;
    double a;           // INPUT: proper acceleration (light-years per year squared)
    double T_target;    // PARAMETER p0: the Earth date ordered for the return (years)
    double fuel_budget; // PARAMETER p1: rapidity the tanks hold
    double a_max;       // PARAMETER p2: the engine's limit
    double beta;        // velocity as a fraction of c, derived, observed

} ModelData;

#endif /* config_h */
