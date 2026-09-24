// The shower plant (see config.h for the story). The controller is NOT in this
// model: the hot fraction is an FMI input a host sets before every communication
// step. No libm calls at all, so the trajectory is plain IEEE arithmetic and does
// not depend on the host machine or the engine.
#include "config.h"
#include "model.h"

static double clamp01(double v) {
    if (v < 0) return 0;
    if (v > 1) return 1;
    return v;
}

Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(T_head) = 12;
    M(a) = 0;
    M(T1) = 12; M(T2) = 12; M(T3) = 12; M(T4) = 12; M(T5) = 12; M(T6) = 12;
    M(u) = 0;
    M(D) = 3;
    M(T_hot) = 60;
    M(t_flush) = 40;
    M(T_cold) = 12;
    // 0.15 lifts a settled 38 C shower to about 42 C, under the 43 C scald line,
    // so the flush costs band time unless the controller compensates; at 0.25 it
    // reaches 44.5 C, and with a 3 s pipe no controller can cut hot in time, so
    // every policy would scald and the flush would teach nothing.
    M(flush_gain) = 0.15;
    M(flush_len) = 12;
    M(tau_v) = 0.5;
    M(tau_h) = 1.0;
    M(T_mix) = 12;

    comp->isDirtyValues = true;

    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    const double u = clamp01(M(u));
    const double flushing = (comp->time >= M(t_flush) && comp->time < M(t_flush) + M(flush_len)) ? M(flush_gain) : 0;
    const double a_eff = clamp01(M(a) * (1 + flushing));
    M(T_mix) = a_eff * M(T_hot) + (1 - a_eff) * M(T_cold);

    M(der_a) = (u - M(a)) / M(tau_v);
    const double k = 6.0 / M(D);
    M(der_T1) = k * (M(T_mix) - M(T1));
    M(der_T2) = k * (M(T1) - M(T2));
    M(der_T3) = k * (M(T2) - M(T3));
    M(der_T4) = k * (M(T3) - M(T4));
    M(der_T5) = k * (M(T4) - M(T5));
    M(der_T6) = k * (M(T5) - M(T6));
    M(der_T_head) = (M(T6) - M(T_head)) / M(tau_h);

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:       ASSERT_NVALUES(1); values[(*index)++] = comp->time;    return OK;
        case vr_T_head:     ASSERT_NVALUES(1); values[(*index)++] = M(T_head);     return OK;
        case vr_der_T_head: ASSERT_NVALUES(1); values[(*index)++] = M(der_T_head); return OK;
        case vr_a:          ASSERT_NVALUES(1); values[(*index)++] = M(a);          return OK;
        case vr_der_a:      ASSERT_NVALUES(1); values[(*index)++] = M(der_a);      return OK;
        case vr_T1:         ASSERT_NVALUES(1); values[(*index)++] = M(T1);         return OK;
        case vr_der_T1:     ASSERT_NVALUES(1); values[(*index)++] = M(der_T1);     return OK;
        case vr_T2:         ASSERT_NVALUES(1); values[(*index)++] = M(T2);         return OK;
        case vr_der_T2:     ASSERT_NVALUES(1); values[(*index)++] = M(der_T2);     return OK;
        case vr_T3:         ASSERT_NVALUES(1); values[(*index)++] = M(T3);         return OK;
        case vr_der_T3:     ASSERT_NVALUES(1); values[(*index)++] = M(der_T3);     return OK;
        case vr_T4:         ASSERT_NVALUES(1); values[(*index)++] = M(T4);         return OK;
        case vr_der_T4:     ASSERT_NVALUES(1); values[(*index)++] = M(der_T4);     return OK;
        case vr_T5:         ASSERT_NVALUES(1); values[(*index)++] = M(T5);         return OK;
        case vr_der_T5:     ASSERT_NVALUES(1); values[(*index)++] = M(der_T5);     return OK;
        case vr_T6:         ASSERT_NVALUES(1); values[(*index)++] = M(T6);         return OK;
        case vr_der_T6:     ASSERT_NVALUES(1); values[(*index)++] = M(der_T6);     return OK;
        case vr_u:          ASSERT_NVALUES(1); values[(*index)++] = M(u);          return OK;
        case vr_D:          ASSERT_NVALUES(1); values[(*index)++] = M(D);          return OK;
        case vr_T_hot:      ASSERT_NVALUES(1); values[(*index)++] = M(T_hot);      return OK;
        case vr_t_flush:    ASSERT_NVALUES(1); values[(*index)++] = M(t_flush);    return OK;
        case vr_T_cold:     ASSERT_NVALUES(1); values[(*index)++] = M(T_cold);     return OK;
        case vr_flush_gain: ASSERT_NVALUES(1); values[(*index)++] = M(flush_gain); return OK;
        case vr_flush_len:  ASSERT_NVALUES(1); values[(*index)++] = M(flush_len);  return OK;
        case vr_tau_v:      ASSERT_NVALUES(1); values[(*index)++] = M(tau_v);      return OK;
        case vr_tau_h:      ASSERT_NVALUES(1); values[(*index)++] = M(tau_h);      return OK;
        case vr_T_mix:      ASSERT_NVALUES(1); values[(*index)++] = M(T_mix);      return OK;
        default:
            logError(comp, "Get Float64 is not allowed for value reference %u.", vr);
            return Error;
    }
}

Status setFloat64(ModelInstance* comp, ValueReference vr, const double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    switch (vr) {
        case vr_T_head: ASSERT_NVALUES(1); M(T_head) = values[(*index)++]; break;
        case vr_a:      ASSERT_NVALUES(1); M(a) = values[(*index)++];      break;
        case vr_T1:     ASSERT_NVALUES(1); M(T1) = values[(*index)++];     break;
        case vr_T2:     ASSERT_NVALUES(1); M(T2) = values[(*index)++];     break;
        case vr_T3:     ASSERT_NVALUES(1); M(T3) = values[(*index)++];     break;
        case vr_T4:     ASSERT_NVALUES(1); M(T4) = values[(*index)++];     break;
        case vr_T5:     ASSERT_NVALUES(1); M(T5) = values[(*index)++];     break;
        case vr_T6:     ASSERT_NVALUES(1); M(T6) = values[(*index)++];     break;
        case vr_u:      ASSERT_NVALUES(1); M(u) = values[(*index)++];      break;
        case vr_D:
        case vr_T_hot:
        case vr_t_flush:
        case vr_T_cold:
        case vr_flush_gain:
        case vr_flush_len:
        case vr_tau_v:
        case vr_tau_h:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_D) M(D) = values[(*index)++];
            else if (vr == vr_T_hot) M(T_hot) = values[(*index)++];
            else if (vr == vr_t_flush) M(t_flush) = values[(*index)++];
            else if (vr == vr_T_cold) M(T_cold) = values[(*index)++];
            else if (vr == vr_flush_gain) M(flush_gain) = values[(*index)++];
            else if (vr == vr_flush_len) M(flush_len) = values[(*index)++];
            else if (vr == vr_tau_v) M(tau_v) = values[(*index)++];
            else M(tau_h) = values[(*index)++];
            break;
        default:
            logError(comp, "Set Float64 is not allowed for value reference %u.", vr);
            return Error;
    }

    comp->isDirtyValues = true;

    return OK;
}

size_t getNumberOfContinuousStates(ModelInstance* comp) {
    UNUSED(comp);
    return MAX_CONTINUOUS_STATES;
}

Status getContinuousStates(ModelInstance *comp, double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    x[0] = M(T_head);
    x[1] = M(a);
    x[2] = M(T1);
    x[3] = M(T2);
    x[4] = M(T3);
    x[5] = M(T4);
    x[6] = M(T5);
    x[7] = M(T6);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    nominals[0] = 40.0;
    nominals[1] = 1.0;
    for (size_t i = 2; i < MAX_CONTINUOUS_STATES; i++) nominals[i] = 40.0;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(T_head) = x[0];
    M(a) = x[1];
    M(T1) = x[2];
    M(T2) = x[3];
    M(T3) = x[4];
    M(T4) = x[5];
    M(T5) = x[6];
    M(T6) = x[7];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_T_head);
    dx[1] = M(der_a);
    dx[2] = M(der_T1);
    dx[3] = M(der_T2);
    dx[4] = M(der_T3);
    dx[5] = M(der_T4);
    dx[6] = M(der_T5);
    dx[7] = M(der_T6);

    return OK;
}

Status eventUpdate(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    comp->valuesOfContinuousStatesChanged   = false;
    comp->nominalsOfContinuousStatesChanged = false;
    comp->terminateSimulation               = false;
    comp->nextEventTimeDefined              = false;

    return OK;
}
