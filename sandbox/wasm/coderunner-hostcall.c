/*
 * Minimal QuickJS-to-wazero bridge for coderunner's host-API broker.
 *
 * The imported function receives only guest-owned request/response buffers. The
 * grant and bearer credential never cross into WASM linear memory. Policy,
 * quotas, upstream HTTP, and response bounds all remain in Go's brokerSession.
 */
#include <stdint.h>

#include "quickjs.h"

#define CODERUNNER_RESPONSE_CAP (4U * 1024U * 1024U)

__attribute__((import_module("coderunner"), import_name("host_call")))
extern uint64_t coderunner_host_call(const uint8_t *request, uint32_t request_len,
                                     uint8_t *response, uint32_t response_cap);

static JSValue js_coderunner_host_call(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv)
{
    const char *request;
    size_t request_len;
    uint8_t *response;
    uint64_t packed;
    uint32_t status;
    uint32_t response_len;
    JSValue result;
    JSValue body;

    (void)this_val;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "host api request envelope is required");

    request = JS_ToCStringLen(ctx, &request_len, argv[0]);
    if (!request)
        return JS_EXCEPTION;
    if (request_len > UINT32_MAX) {
        JS_FreeCString(ctx, request);
        return JS_ThrowRangeError(ctx, "host api request envelope is too large");
    }

    response = js_malloc(ctx, CODERUNNER_RESPONSE_CAP);
    if (!response) {
        JS_FreeCString(ctx, request);
        return JS_EXCEPTION;
    }
    packed = coderunner_host_call((const uint8_t *)request, (uint32_t)request_len,
                                  response, CODERUNNER_RESPONSE_CAP);
    JS_FreeCString(ctx, request);

    status = (uint32_t)(packed >> 32);
    response_len = (uint32_t)packed;
    if (status < 100 || status > 599 || response_len > CODERUNNER_RESPONSE_CAP) {
        js_free(ctx, response);
        return JS_ThrowInternalError(ctx, "host api bridge returned an invalid response");
    }

    body = JS_NewStringLen(ctx, (const char *)response, response_len);
    js_free(ctx, response);
    if (JS_IsException(body))
        return body;

    result = JS_NewObject(ctx);
    if (JS_IsException(result)) {
        JS_FreeValue(ctx, body);
        return result;
    }
    if (JS_SetPropertyStr(ctx, result, "status", JS_NewUint32(ctx, status)) < 0) {
        JS_FreeValue(ctx, body);
        JS_FreeValue(ctx, result);
        return JS_EXCEPTION;
    }
    if (JS_SetPropertyStr(ctx, result, "body", body) < 0) {
        JS_FreeValue(ctx, result);
        return JS_EXCEPTION;
    }
    return result;
}

void coderunner_register_hostcall(JSContext *ctx)
{
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue function = JS_NewCFunction(ctx, js_coderunner_host_call,
                                       "__coderunner_host_call", 1);
    JS_DefinePropertyValueStr(ctx, global, "__coderunner_host_call", function,
                              JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE);
    JS_FreeValue(ctx, global);
}
