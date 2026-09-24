// The relativistic clock-steering plant (see config.h). The controller is NOT in
// this model: the frequency correction is an FMI input a host sets before every
// communication step. sin comes from wasi-libc inside the module.
#include <math.h>
#include "config.h"
#include "model.h"

Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(x) = 0;
    M(d1) = 0; M(d2) = 0; M(d3) = 0; M(d4) = 0; M(d5) = 0; M(d6) = 0;
    M(u) = 0;
    M(e) = 0.02;
    M(y0) = 0;
    M(D) = 600;
    M(rate_gr) = 38.6e-6 / 86400;   // 4.47e-10 s/s
    M(ecc_amp) = 2.29e-6;           // s per unit eccentricity: 2 sqrt(GM a) / c^2 for a = 26,560 km
    M(omega) = 2 * M_PI / (12 * 3600);
    M(u_max) = 1e-8;

    comp->isDirtyValues = true;

    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    double u = M(u);
    if (u > M(u_max)) u = M(u_max);
    if (u < -M(u_max)) u = -M(u_max);
    // The eccentricity term is a time offset e * ecc_amp * sin(omega t); its rate
    // is the derivative.
    const double eccRate = M(e) * M(ecc_amp) * M(omega) * cos(M(omega) * comp->time);
    M(der_x) = M(rate_gr) + eccRate + M(y0) + u;
    const double k = 6.0 / M(D);
    M(der_d1) = k * (M(x) - M(d1));
    M(der_d2) = k * (M(d1) - M(d2));
    M(der_d3) = k * (M(d2) - M(d3));
    M(der_d4) = k * (M(d3) - M(d4));
    M(der_d5) = k * (M(d4) - M(d5));
    M(der_d6) = k * (M(d5) - M(d6));

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:    ASSERT_NVALUES(1); values[(*index)++] = comp->time; return OK;
        case vr_x:       ASSERT_NVALUES(1); values[(*index)++] = M(x);       return OK;
        case vr_der_x:   ASSERT_NVALUES(1); values[(*index)++] = M(der_x);   return OK;
        case vr_d1:      ASSERT_NVALUES(1); values[(*index)++] = M(d1);      return OK;
        case vr_der_d1:  ASSERT_NVALUES(1); values[(*index)++] = M(der_d1);  return OK;
        case vr_d2:      ASSERT_NVALUES(1); values[(*index)++] = M(d2);      return OK;
        case vr_der_d2:  ASSERT_NVALUES(1); values[(*index)++] = M(der_d2);  return OK;
        case vr_d3:      ASSERT_NVALUES(1); values[(*index)++] = M(d3);      return OK;
        case vr_der_d3:  ASSERT_NVALUES(1); values[(*index)++] = M(der_d3);  return OK;
        case vr_d4:      ASSERT_NVALUES(1); values[(*index)++] = M(d4);      return OK;
        case vr_der_d4:  ASSERT_NVALUES(1); values[(*index)++] = M(der_d4);  return OK;
        case vr_d5:      ASSERT_NVALUES(1); values[(*index)++] = M(d5);      return OK;
        case vr_der_d5:  ASSERT_NVALUES(1); values[(*index)++] = M(der_d5);  return OK;
        case vr_d6:      ASSERT_NVALUES(1); values[(*index)++] = M(d6);      return OK;
        case vr_der_d6:  ASSERT_NVALUES(1); values[(*index)++] = M(der_d6);  return OK;
        case vr_u:       ASSERT_NVALUES(1); values[(*index)++] = M(u);       return OK;
        case vr_e:       ASSERT_NVALUES(1); values[(*index)++] = M(e);       return OK;
        case vr_y0:      ASSERT_NVALUES(1); values[(*index)++] = M(y0);      return OK;
        case vr_D:       ASSERT_NVALUES(1); values[(*index)++] = M(D);       return OK;
        case vr_rate_gr: ASSERT_NVALUES(1); values[(*index)++] = M(rate_gr); return OK;
        case vr_ecc_amp: ASSERT_NVALUES(1); values[(*index)++] = M(ecc_amp); return OK;
        case vr_omega:   ASSERT_NVALUES(1); values[(*index)++] = M(omega);   return OK;
        case vr_u_max:   ASSERT_NVALUES(1); values[(*index)++] = M(u_max);   return OK;
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
        case vr_x:  ASSERT_NVALUES(1); M(x) = values[(*index)++];  break;
        case vr_d1: ASSERT_NVALUES(1); M(d1) = values[(*index)++]; break;
        case vr_d2: ASSERT_NVALUES(1); M(d2) = values[(*index)++]; break;
        case vr_d3: ASSERT_NVALUES(1); M(d3) = values[(*index)++]; break;
        case vr_d4: ASSERT_NVALUES(1); M(d4) = values[(*index)++]; break;
        case vr_d5: ASSERT_NVALUES(1); M(d5) = values[(*index)++]; break;
        case vr_d6: ASSERT_NVALUES(1); M(d6) = values[(*index)++]; break;
        case vr_u:  ASSERT_NVALUES(1); M(u) = values[(*index)++];  break;
        case vr_e:
        case vr_y0:
        case vr_D:
        case vr_rate_gr:
        case vr_ecc_amp:
        case vr_omega:
        case vr_u_max:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_e) M(e) = values[(*index)++];
            else if (vr == vr_y0) M(y0) = values[(*index)++];
            else if (vr == vr_D) M(D) = values[(*index)++];
            else if (vr == vr_rate_gr) M(rate_gr) = values[(*index)++];
            else if (vr == vr_ecc_amp) M(ecc_amp) = values[(*index)++];
            else if (vr == vr_omega) M(omega) = values[(*index)++];
            else M(u_max) = values[(*index)++];
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

    x[0] = M(x); x[1] = M(d1); x[2] = M(d2); x[3] = M(d3); x[4] = M(d4); x[5] = M(d5); x[6] = M(d6);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    for (size_t i = 0; i < MAX_CONTINUOUS_STATES; i++) nominals[i] = 1e-6;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(x) = x[0]; M(d1) = x[1]; M(d2) = x[2]; M(d3) = x[3]; M(d4) = x[4]; M(d5) = x[5]; M(d6) = x[6];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_x); dx[1] = M(der_d1); dx[2] = M(der_d2); dx[3] = M(der_d3); dx[4] = M(der_d4); dx[5] = M(der_d5); dx[6] = M(der_d6);

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
