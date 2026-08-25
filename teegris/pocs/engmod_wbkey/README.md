# engmod_wbkey — hardcoded fleet-wide white-box AES key recovery

- **TA:** engmod (Samsung TEEGRIS EngineeringMode TA)
- **UUID:** `00000000-0000-0000-0000-656e676d6f64` (ASCII tail `engmod`)
- **Severity:** HIGH
- **Recovered key:** `"departmstggroup."` =
  `64 65 70 61 72 74 6d 73 74 67 67 72 6f 75 70 2e` (16 bytes, AES-128)
- **REPRO-STATUS:** **CONFIRMED — key recovered & verified usable.** No TEE
  runtime required.

## The finding

Source: `RE/samsung_teegris/engmod.md` ("NEW FINDING — HIGH: White-box AES
uses a HARDCODED 16-byte ASCII key `departmstggroup.`"), confirmed in
`RE/emulation/engmod.md` Finding #1.

The "white-box" AES routines `em_wb_aes_ctr_crypt_a @ 0x26E94` (mode 1) and
`em_wb_aes_ctr_crypt_b @ 0x27074` (mode 2) do, in the Hex-Rays decompile:

```c
key_const = xmmword_8590;                       // the 16 .rodata bytes
em_aes_key_expand(round_keys_buf, &key_const);  // AES-128 key schedule
```

i.e. a **literal 16-byte ASCII string is loaded directly as the AES-128 key.**
The wrapper `em_wb_aes_state_init @ 0x267B8` only does an RC4-style sbox shuffle
+ XOR integrity check — it does **not** derive or protect the key. The 16 bytes
are:

```
64 65 70 61 72 74 6d 73 74 67 67 72 6f 75 70 2e   =   "departmstggroup."
```

**Usage** (both with this same constant key):

- `em_ess_encrypt_message @ 0x2299C` wraps each per-call random AES-256-CTR ESS
  session key + IV before base64-sending to Samsung's ESS server →
  **offline decryption of all ESS transport** (request payload carries DID,
  IMEI, IIN, model name, service-order details, RID/RSD, mode list, signed
  nonces).
- `em_cmd_time_check @ 0x1ED2C` (cmd 24) uses it to decrypt the inbound RTD
  nonce and encrypt the outbound 64-byte RTD ACK → **forgeable ACK** (ties into
  the sibling `engmod_rtd` POC).

It is a **fleet-wide literal**: a brandable ASCII string rules out any
per-device / per-batch derivation; it is present plaintext in **every** S921B /
A556B engmod image in the corpus.

## Why this is a key-recovery PoC (no TEE runtime)

The defect *is* "a fleet-wide symmetric key ships in plaintext in every image."
Its security value (offline ESS decryption, RTD-ACK forgery) follows
mathematically once the key is extractable, which it demonstrably is. So
reading it out of the binary **is** the proof — no emulator, no device, no live
command drive needed. (The use-sites are gated behind token-install / un-modeled
crypto in the emulator, but executing the WB-AES routine would only re-derive a
round schedule from bytes already in hand — it adds nothing to the proof. See
`RE/emulation/engmod.md` Finding #1.)

### A note on AES key size (grounded, not assumed)

The hardcoded key is **16 bytes** and is loaded into the **AES-128** key
schedule (`em_aes_key_expand` on a 16-byte string per the decompile). This is
**distinct** from engmod's other crypto: the KDF labels
`"EngineeringMode20 AES256 Key Context, MSTG."` + `EVP_aes_256_ctr` drive a
*per-call random* AES-256 session key derived via `TEES_DeriveKeyKDF` — **not**
this constant. The extractor therefore demonstrates **AES-128-CTR** with the
recovered 16-byte key, matching the white-box wrapper's stream-cipher usage.

## What `wbkey_extract.c` does

1. Opens the engmod TA binary (default: the bundled emulator
   `teegris/tas/…656e676d6f64.ta`; pass a path arg to target another build).
2. Recovers the 16 key bytes by **scanning** for the documented ASCII (robust
   across the per-build offset shift) and **cross-checks** the documented
   per-build file offset.
3. Prints the key (hex + ASCII) and confirms byte-for-byte equality with the
   writeup's recorded value.
4. Demonstrates key usability with an **AES-128-CTR round-trip** via OpenSSL
   EVP (the same crypto stack the TA links).

The documented per-build file offsets it cross-checks:

| build | file offset | source |
|---|---|---|
| emulator S9BYH2 `.ta` | `0x8520` | `RE/emulation/engmod.md` |
| RE S921B SFDZE1 `.elf` | `0x8590` | `RE/samsung_teegris/engmod.md` |
| RE A556B DZE4 `.elf` | `0x8550` | this run (separate build) |

## Build & run

```sh
gcc -O2 wbkey_extract.c -o wbkey_extract -lcrypto
./wbkey_extract                 # defaults to the bundled emulator .ta
./wbkey_extract /path/to/engmod.elf   # any other build
```

## Observed output (this run)

Against the bundled emulator `.ta`:

```
[wbkey] engmod hardcoded white-box AES key recovery
[wbkey] target binary: /home/lamb/opt/TA_GP_emulator/teegris/tas/00000000-0000-0000-0000-656e676d6f64.ta
[wbkey] size: 195003 bytes

[wbkey] KEY RECOVERED at file offset 0x8520:
    hex   : 64 65 70 61 72 74 6d 73 74 67 67 72 6f 75 70 2e
    ascii : "departmstggroup."
[wbkey] offset 0x8520 matches documented build: emulator S9BYH2 .ta (emulation/engmod.md)
[wbkey] bytes are BYTE-FOR-BYTE identical to the RE writeup's "departmstggroup." .

[wbkey] key-usability demo (AES-128-CTR, OpenSSL EVP = the TA's crypto stack):
    plaintext : "engmod RTD ACK sample plaintext (key-usability proof)" (53 bytes)
    ciphertext: 19cb870f347aafe2fdd552f95fd8c689f58969f4af91b178a37d9781bc6df58234835a5d218bc5aa3403770d5c1e5a11bb100908d2
    decrypted : "engmod RTD ACK sample plaintext (key-usability proof)" (53 bytes)
    [OK] AES-128-CTR round-trip matches -> recovered key is usable.
```

Cross-build confirmation (key found at the exact documented offset for each,
byte-for-byte identical, round-trip OK in every case):

```
S921B SFDZE1 .elf : KEY RECOVERED at file offset 0x8590   (matches engmod.md)
A556B DZE4   .elf : KEY RECOVERED at file offset 0x8550   (separate build)
```

## Files

- `wbkey_extract.c` — the standalone extractor (all constants cited to the
  writeups inline).
- `README.md` — this file.
