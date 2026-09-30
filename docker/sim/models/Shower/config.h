// Flow-based shower: independent hot/cold valves, stored water in both supply
// branches, a mixer and a shared outlet. No recirculation. See physics.h for the
// common hydraulic and finite-volume thermal kernel and its assumptions.
#ifndef config_h
#define config_h
#include "physics.h"
#define MODEL_IDENTIFIER Shower
#define INSTANTIATION_TOKEN "{7A3E5C10-9B2D-4F61-8E47-2C1D5B9F0A63}"
#define CO_SIMULATION
#define MODEL_EXCHANGE
#define MAX_CONTINUOUS_STATES SHOWER_NX
#define SET_FLOAT64
// At allowed minimum volumes and maximum pressures, the largest Euler transport
// coefficient is below 1, so a cell cannot numerically jump beyond its inputs.
#define FIXED_SOLVER_STEP SHOWER_DT
#define DEFAULT_STOP_TIME 90

// States occupy odd references 1..2*NX-1, their derivatives the next even one.
typedef enum {
    vr_time = 0,
    vr_u_hot = 2 * SHOWER_NX + 1, vr_u_cold,
    vr_hot_volume, vr_hot_temperature, vr_flush_time,
    vr_cold_volume, vr_outlet_volume, vr_cold_temperature, vr_ambient_temperature,
    vr_cooling_time, vr_hot_pressure, vr_cold_pressure, vr_flush_pressure_fraction,
    vr_flush_length, vr_hot_flow, vr_cold_flow
} ValueReference;
typedef struct {
    double x[SHOWER_NX], dx[SHOWER_NX], u[2];
    ShowerParameters p;
    ShowerFlow flow;
} ModelData;
#endif
