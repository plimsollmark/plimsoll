// Vendored from the plimsoll-sim repository at commit d3f9b28 (2026-09-18),
// unchanged below this header. The cart-pole plant of the physics oracle, in the
// Reference FMU style (models/CartPole there).
#ifndef config_h
#define config_h

// define class name and unique id
#define MODEL_IDENTIFIER CartPole
#define INSTANTIATION_TOKEN "{BFE341C2-CAE8-4202-9242-30BE8F255E82}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 4

#define SET_FLOAT64

// Ten forward Euler steps per 10 ms communication step (the Reference FMUs'
// solver), enough for a balancing demo; not a claim about accuracy.
#define FIXED_SOLVER_STEP 1e-3
#define DEFAULT_STOP_TIME 20

typedef enum {
    vr_time, vr_x, vr_der_x, vr_v, vr_der_v, vr_theta, vr_der_theta, vr_omega, vr_der_omega,
    vr_F, vr_l, vr_M, vr_m, vr_g, vr_Fmax
} ValueReference;

typedef struct {

    double x;         // cart position (m)
    double der_x;
    double v;         // cart velocity (m/s)
    double der_v;
    double theta;     // pole angle from upright (rad); positive leans toward +x
    double der_theta;
    double omega;     // pole angular velocity (rad/s)
    double der_omega;
    double F;         // INPUT: force on the cart (N), the controller's decision
    double l;         // pole half-length (m)
    double M;         // cart mass (kg)
    double m;         // pole mass (kg)
    double g;         // gravity (m/s^2)
    double Fmax;      // actuator limit (N): |F| is clamped to it

} ModelData;

#endif /* config_h */
