// The shower plant of the control-design environments, in the Reference FMU style:
// built against the Reference FMUs' fmi3Functions.c and cosimulation.c like their
// own models, and stepped by sim/shim_env.c with the value references in plant.h.
//
// A mixing valve feeds a pipe that feeds a shower head. The controller commands
// the hot fraction; it observes the head temperature and the valve position. The
// pipe is a transport delay (a chain of six first-order lags), the head a thermal
// mass, the valve a rate-limited actuator, and at t_flush someone flushes a toilet:
// the cold supply loses pressure for flush_len seconds, so the same valve position
// runs hotter. The hard failure is a scald, and the delay is what makes it hard.
#ifndef config_h
#define config_h

#define MODEL_IDENTIFIER Shower
#define INSTANTIATION_TOKEN "{7A3E5C10-9B2D-4F61-8E47-2C1D5B9F0A63}"

#define CO_SIMULATION
#define MODEL_EXCHANGE

#define MAX_CONTINUOUS_STATES 8

#define SET_FLOAT64

// Ten forward Euler steps per 100 ms communication step. The fastest time constant
// is the delay chain at D/6 with D >= 1 s, so 10 ms is well inside stability.
#define FIXED_SOLVER_STEP 1e-2
#define DEFAULT_STOP_TIME 90

typedef enum {
    vr_time,
    vr_T_head, vr_der_T_head,
    vr_a, vr_der_a,
    vr_T1, vr_der_T1, vr_T2, vr_der_T2, vr_T3, vr_der_T3,
    vr_T4, vr_der_T4, vr_T5, vr_der_T5, vr_T6, vr_der_T6,
    vr_u,
    vr_D, vr_T_hot, vr_t_flush,
    vr_T_cold, vr_flush_gain, vr_flush_len, vr_tau_v, vr_tau_h,
    vr_T_mix
} ValueReference;

typedef struct {

    double T_head;      // temperature at the shower head (C): what the person feels
    double der_T_head;
    double a;           // valve position, hot fraction actually admitted (0..1)
    double der_a;
    double T1, der_T1;  // the pipe: six lags in series approximating a delay of D
    double T2, der_T2;
    double T3, der_T3;
    double T4, der_T4;
    double T5, der_T5;
    double T6, der_T6;
    double u;           // INPUT: commanded hot fraction (0..1), the controller's decision
    double D;           // PARAMETER p0: pipe transport delay (s)
    double T_hot;       // PARAMETER p1: hot supply temperature (C)
    double t_flush;     // PARAMETER p2: when the toilet is flushed (s)
    double T_cold;      // cold supply temperature (C)
    double flush_gain;  // during the flush the admitted hot fraction is a*(1+flush_gain)
    double flush_len;   // how long the flush starves the cold supply (s)
    double tau_v;       // valve actuator time constant (s)
    double tau_h;       // shower head thermal time constant (s)
    double T_mix;       // temperature leaving the valve (C), derived, not observed

} ModelData;

#endif /* config_h */
