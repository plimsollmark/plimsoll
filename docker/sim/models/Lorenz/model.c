// Vendored from the plimsoll-sim repository at commit 0be8574 (2026-09-18),
// unchanged below this header. The Lorenz model of our own, in the Reference FMU style
// (models/Lorenz there); built against the Reference FMUs' fmi3Functions.c and
// cosimulation.c like their own models.
#include "config.h"
#include "model.h"


Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(x) = 1;
    M(y) = 1;
    M(z) = 1;
    M(sigma) = 10;
    M(rho) = 28;
    M(beta) = 8.0 / 3.0;

    comp->isDirtyValues = true;

    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(der_x) = M(sigma) * (M(y) - M(x));
    M(der_y) = M(x) * (M(rho) - M(z)) - M(y);
    M(der_z) = M(x) * M(y) - M(beta) * M(z);

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:
            ASSERT_NVALUES(1);
            values[(*index)++] = comp->time;
            return OK;
        case vr_x:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(x);
            return OK;
        case vr_der_x:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(der_x);
            return OK;
        case vr_y:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(y);
            return OK;
        case vr_der_y:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(der_y);
            return OK;
        case vr_z:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(z);
            return OK;
        case vr_der_z:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(der_z);
            return OK;
        case vr_sigma:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(sigma);
            return OK;
        case vr_rho:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(rho);
            return OK;
        case vr_beta:
            ASSERT_NVALUES(1);
            values[(*index)++] = M(beta);
            return OK;
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
        case vr_x:
            ASSERT_NVALUES(1);
            M(x) = values[(*index)++];
            break;
        case vr_y:
            ASSERT_NVALUES(1);
            M(y) = values[(*index)++];
            break;
        case vr_z:
            ASSERT_NVALUES(1);
            M(z) = values[(*index)++];
            break;
        case vr_sigma:
        case vr_rho:
        case vr_beta:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_sigma) M(sigma) = values[(*index)++];
            else if (vr == vr_rho) M(rho) = values[(*index)++];
            else M(beta) = values[(*index)++];
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

    x[0] = M(x);
    x[1] = M(y);
    x[2] = M(z);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    nominals[0] = 1.0;
    nominals[1] = 1.0;
    nominals[2] = 1.0;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(x) = x[0];
    M(y) = x[1];
    M(z) = x[2];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_x);
    dx[1] = M(der_y);
    dx[2] = M(der_z);

    return OK;
}

Status getPartialDerivative(ModelInstance *comp, ValueReference unknown, ValueReference known, double *partialDerivative) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(partialDerivative);

    if (unknown == vr_der_x && known == vr_x) {
        *partialDerivative = -M(sigma);
    } else if (unknown == vr_der_x && known == vr_y) {
        *partialDerivative = M(sigma);
    } else if (unknown == vr_der_y && known == vr_x) {
        *partialDerivative = M(rho) - M(z);
    } else if (unknown == vr_der_y && known == vr_y) {
        *partialDerivative = -1;
    } else if (unknown == vr_der_y && known == vr_z) {
        *partialDerivative = -M(x);
    } else if (unknown == vr_der_z && known == vr_x) {
        *partialDerivative = M(y);
    } else if (unknown == vr_der_z && known == vr_y) {
        *partialDerivative = M(x);
    } else if (unknown == vr_der_z && known == vr_z) {
        *partialDerivative = -M(beta);
    } else if (unknown == vr_der_x && known == vr_sigma && comp->state == InitializationMode) {
        *partialDerivative = M(y) - M(x);
    } else if (unknown == vr_der_y && known == vr_rho && comp->state == InitializationMode) {
        *partialDerivative = M(x);
    } else if (unknown == vr_der_z && known == vr_beta && comp->state == InitializationMode) {
        *partialDerivative = -M(z);
    } else {
        *partialDerivative = 0;
    }

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
