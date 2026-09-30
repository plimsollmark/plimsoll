// FMI wrapper around the shared plumbing kernel. The controller receives no
// scenario parameters; all state is local to this plant instance.
#include "config.h"
#include "model.h"

Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);
    M(p) = (ShowerParameters){.hot_volume = 0.3, .hot_temperature = 60, .flush_time = 40,
        .cold_volume = 0.2, .outlet_volume = 0.12, .cold_temperature = 12,
        .ambient_temperature = 20, .cooling_time = 600, .hot_pressure = 3,
        .cold_pressure = 3, .flush_pressure_fraction = 0.8, .flush_length = 12};
    for (size_t i = 0; i < SHOWER_NX; i++) {
        M(x)[i] = i >= SHOWER_HOT && i < SHOWER_VOLUME ? 20 : 0;
        M(dx)[i] = 0;
    }
    M(u)[0] = M(u)[1] = 0;
    comp->isDirtyValues = true;
    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);
    M(flow) = shower_rhs(comp->time, &M(p), M(x), M(u), M(dx));
    comp->isDirtyValues = false;
    return OK;
}

static double *parameter(ModelInstance *comp, ValueReference vr) {
    switch (vr) {
        case vr_hot_volume: return &M(p).hot_volume;
        case vr_hot_temperature: return &M(p).hot_temperature;
        case vr_flush_time: return &M(p).flush_time;
        case vr_cold_volume: return &M(p).cold_volume;
        case vr_outlet_volume: return &M(p).outlet_volume;
        case vr_cold_temperature: return &M(p).cold_temperature;
        case vr_ambient_temperature: return &M(p).ambient_temperature;
        case vr_cooling_time: return &M(p).cooling_time;
        case vr_hot_pressure: return &M(p).hot_pressure;
        case vr_cold_pressure: return &M(p).cold_pressure;
        case vr_flush_pressure_fraction: return &M(p).flush_pressure_fraction;
        case vr_flush_length: return &M(p).flush_length;
        default: return NULL;
    }
}

static int validParameter(ValueReference vr, double v) {
    if (!isfinite(v)) return 0;
    switch (vr) {
        case vr_hot_volume: case vr_cold_volume: case vr_outlet_volume: return v >= 0.05 && v <= 5;
        case vr_hot_pressure: case vr_cold_pressure: return v >= 0.1 && v <= 10;
        case vr_hot_temperature: case vr_cold_temperature: return v >= 0 && v <= 95;
        case vr_ambient_temperature: return v >= -10 && v <= 60;
        case vr_cooling_time: return v == 0 || v >= 10;
        case vr_flush_pressure_fraction: return v >= 0 && v <= 1;
        case vr_flush_time: case vr_flush_length: return v >= 0;
        default: return 0;
    }
}

Status getFloat64(ModelInstance *comp, ValueReference vr, double values[], size_t nValues, size_t *index) {
    ASSERT_NOT_NULL2(comp); ASSERT_NOT_NULL2(values); ASSERT_NOT_NULL2(index);
    ASSERT_NVALUES(1);
    calculateValues(comp);
    double v;
    if (vr > 0 && vr <= 2 * SHOWER_NX) v = vr % 2 ? M(x)[(vr - 1) / 2] : M(dx)[(vr - 2) / 2];
    else if (vr == vr_time) v = comp->time;
    else if (vr == vr_u_hot || vr == vr_u_cold) v = M(u)[vr - vr_u_hot];
    else if (vr == vr_hot_flow) v = M(flow).hot;
    else if (vr == vr_cold_flow) v = M(flow).cold;
    else {
        double *p = parameter(comp, vr);
        if (!p) { logError(comp, "Unknown Float64 reference %u.", vr); return Error; }
        v = *p;
    }
    values[(*index)++] = v;
    return OK;
}

Status setFloat64(ModelInstance *comp, ValueReference vr, const double values[], size_t nValues, size_t *index) {
    ASSERT_NOT_NULL2(comp); ASSERT_NOT_NULL2(values); ASSERT_NOT_NULL2(index);
    ASSERT_NVALUES(1);
    const double v = values[(*index)++];
    if (!isfinite(v)) { logError(comp, "Nonfinite value for reference %u.", vr); return Error; }
    if (vr > 0 && vr < 2 * SHOWER_NX && vr % 2) M(x)[(vr - 1) / 2] = v;
    else if (vr == vr_u_hot || vr == vr_u_cold) {
        M(u)[vr - vr_u_hot] = v < 0 ? 0 : v > 1 ? 1 : v;
    } else {
        double *p = parameter(comp, vr);
        if (!p || !validParameter(vr, v)) { logError(comp, "Invalid parameter %u.", vr); return Error; }
        if (comp->type == ModelExchange && comp->state != Instantiated &&
            comp->state != InitializationMode && comp->state != EventMode) return Error;
        *p = v;
    }
    comp->isDirtyValues = true;
    return OK;
}

size_t getNumberOfContinuousStates(ModelInstance *comp) { UNUSED(comp); return SHOWER_NX; }
Status getContinuousStates(ModelInstance *comp, double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp); ASSERT_NOT_NULL2(x); ASSERT_SIZE_T(nx, SHOWER_NX);
    for (size_t i = 0; i < nx; i++) x[i] = M(x)[i];
    return OK;
}
Status getNominalsOfContinuousStates(ModelInstance *comp, double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp); ASSERT_NOT_NULL2(x); ASSERT_SIZE_T(nx, SHOWER_NX);
    for (size_t i = 0; i < nx; i++) x[i] = i >= SHOWER_HOT && i < SHOWER_VOLUME ? 40 : 1;
    return OK;
}
Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp); ASSERT_NOT_NULL2(x); ASSERT_SIZE_T(nx, SHOWER_NX);
    for (size_t i = 0; i < nx; i++) { if (!isfinite(x[i])) return Error; M(x)[i] = x[i]; }
    comp->isDirtyValues = true;
    return OK;
}
Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp); ASSERT_NOT_NULL2(dx); ASSERT_SIZE_T(nx, SHOWER_NX);
    calculateValues(comp);
    for (size_t i = 0; i < nx; i++) dx[i] = M(dx)[i];
    return OK;
}
Status eventUpdate(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);
    comp->valuesOfContinuousStatesChanged = false;
    comp->nominalsOfContinuousStatesChanged = false;
    comp->terminateSimulation = false;
    comp->nextEventTimeDefined = false;
    return OK;
}
