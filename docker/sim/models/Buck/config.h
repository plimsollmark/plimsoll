// The buck-converter plant of the control-design environments, in the Reference
// FMU style, stepped by sim/shim_env.c with the value references in plant.h.
//
// The averaged model of a synchronous buck converter: the inductor sees the duty
// cycle times the input voltage minus the output voltage, the capacitor sees the
// inductor current minus the load current. At t_step the load resistance halves
// (a load step, the disturbance every regulator is judged on). The controller
// commands the duty cycle and observes output voltage and inductor current.
#ifndef config_h
#define config_h

#define MODEL_IDENTIFIER Buck
#define INSTANTIATION_TOKEN "{9F4B2A6C-1D7E-4B35-8C2A-3E6F9D1B5A70}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 2

#define SET_FLOAT64

// Ten forward Euler steps per 10 us communication step (a 100 kHz control loop).
// The LC resonance is 1.6 kHz, so 1 us is two hundred times inside stability.
#define FIXED_SOLVER_STEP 1e-6
#define DEFAULT_STOP_TIME 0.02

typedef enum {
    vr_time,
    vr_v, vr_der_v,
    vr_i, vr_der_i,
    vr_u,
    vr_Vin, vr_R0, vr_t_step,
    vr_L, vr_C, vr_R
} ValueReference;

typedef struct {

    double v;       // output voltage (V)
    double der_v;
    double i;       // inductor current (A)
    double der_i;
    double u;       // INPUT: duty cycle (0..1), the controller's decision
    double Vin;     // PARAMETER p0: input voltage (V)
    double R0;      // PARAMETER p1: load resistance before the step (ohm)
    double t_step;  // PARAMETER p2: when the load resistance halves (s)
    double L;       // inductance (H)
    double C;       // capacitance (F)
    double R;       // load resistance now (ohm), derived

} ModelData;

#endif /* config_h */
