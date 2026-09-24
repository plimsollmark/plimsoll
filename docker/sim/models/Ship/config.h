// The ship-heading plant of the control-design environments, in the Reference FMU
// style, stepped by sim/shim_env.c with the value references in plant.h.
//
// A first-order Nomoto model: the yaw rate answers the rudder through a gain K
// and a time constant T, and the heading is the integral of the yaw rate. The
// rudder is a real actuator (a lag, a rate limit and a hard stop), and waves
// push the bow with a periodic yaw acceleration. The controller commands the
// rudder angle and observes heading, yaw rate and the rudder's actual angle.
#ifndef config_h
#define config_h

#define MODEL_IDENTIFIER Ship
#define INSTANTIATION_TOKEN "{2C9D7E41-5B3A-4F08-9A1C-6E2B8D4F7A15}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 3

#define SET_FLOAT64

// Ten forward Euler steps per 0.5 s communication step. The fastest dynamics are
// the rudder lag (2 s) and the waves (a 12.6 s period), both far above 50 ms.
#define FIXED_SOLVER_STEP 5e-2
#define DEFAULT_STOP_TIME 300

typedef enum {
    vr_time,
    vr_psi, vr_der_psi,
    vr_r, vr_der_r,
    vr_delta, vr_der_delta,
    vr_u,
    vr_K, vr_T, vr_wave,
    vr_wave_omega, vr_delta_max, vr_delta_rate, vr_tau_r
} ValueReference;

typedef struct {

    double psi;         // heading (rad), 0 is the initial course
    double der_psi;
    double r;           // yaw rate (rad/s)
    double der_r;
    double delta;       // rudder angle actually reached (rad)
    double der_delta;
    double u;           // INPUT: commanded rudder angle (rad), the controller's decision
    double K;           // PARAMETER p0: Nomoto gain (1/s)
    double T;           // PARAMETER p1: Nomoto time constant (s)
    double wave;        // PARAMETER p2: wave yaw-acceleration amplitude (rad/s^2)
    double wave_omega;  // wave encounter frequency (rad/s)
    double delta_max;   // rudder hard stop (rad): |delta| and |u| are clamped to it
    double delta_rate;  // rudder slew limit (rad/s)
    double tau_r;       // rudder actuator lag (s)

} ModelData;

#endif /* config_h */
