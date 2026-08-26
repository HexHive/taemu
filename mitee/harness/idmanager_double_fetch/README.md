# S26-1 — idmanager `cmd 0x002` double-fetch → heap overflow (TA_GP_emulator reproducer)

Deterministic in-emulator reproduction of **S26-1**: an **unauthenticated**
REE→TEE **double-fetch / TOCTOU** (CWE-367) in the Xiaomi MiTEE *idmanager* TA
(`8aaaf201-2460-0000-aabbccdd00000006`, klee / MT6899) that yields a ~6 KB
**heap buffer overflow** (and persistent RPMB identity-blob tamper).

- Finding: `docs/submissions/S26_xiaomi_mitee_double_fetch.md` (S26-1),
  `docs/bugs/xiaomi_s26-1.md`, triage `RE/triage/mitee_double_fetch_manual.md` (DF-1).
- RE: `RE/xiaomi_mitee/mitee_idmanager.md`.
- Driven on the **shipped klee build** — the staged `.ta` is
  `sha256 47d81e49…`, the exact binary the writeup offsets come from.

## The bug (disasm-confirmed on this `.ta`)

`TA_InvokeCommandEntryPoint @0x20098` gates **only** `paramTypes==0x65`
(p0=MEMREF_INPUT, p1=MEMREF_OUTPUT), `params[0].size==0x2008`,
`params[1].size==0x2008`, `*(u32*)p0.buf==1` (version). **No auth**
(`do_auth_token_check` runs only for cmd `0x103`/`0x105`).

Handler `cmd_write_misecids @0x20458` reads the inner length `[p0.buf+4]`
**twice** from the still-shared input MEMREF VMO, with **no copy-in** between:

```
read#1  @0x2046c   ldr w8,[x0,#4]    -> len1 ; gates ecc_verify over (len1-64) bytes
read#2  @0x204f0   ldr w1,[x20,#4]   -> len2 ; -> secure_id_write @0x21fa0:
                       xiaomi_malloc(0x800)                       ; 2048-byte chunk
                       memmove(chunk, p0.buf+8, len2) @0x22014    ; <-- OVERFLOW
                       rpmb_write(slot0, chunk, 0x800)            ; persist
```

`len2` is **unclamped** (bounded only by `p0.size==0x2008`). A normal-world
thread that flips `[p0.buf+4]` from a small `len1` (so the signature covers a
tiny prefix and the gate passes) to a large `len2` between the two reads
overflows the 2048-byte chunk with ~6 KB of attacker content, and persists
bytes *beyond* the signed `(len1-64)` region into the misecids RPMB
identity/attestation blob.

## What the harness does

`harness.py` drives one `TEE_InvokeCommand(cmd=0x002, paramTypes=0x65)` with a
well-formed envelope and models the **perfectly-timed** REE writer by serving
`[p0.buf+4]` two different values across its two reads, keyed on the reading PC:

- at **read#1** (`PC 0x2046c`) the field reads `len1 = 0x80` (the "signed prefix"),
- at **read#2** (`PC 0x204f0`) the field reads `len2 = 0x2000` → the over-long copy.

This is exactly the value a concurrent normal-world writer interposes, and is how
the TA_GP_emulator demonstrates double-fetches generally (`params.py`
`TAEMU_DOUBLE_FETCH`; `pocs/377e_double_fetch_stackov`).

Two code hooks (`init_fuzz`) make the gated sink reachable and the overflow
detectable — both clearly-labelled **models**, not part of the bug:

- **`ecc_verify @0x21088` → return 0.** The provisioned ECDSA-P256 pubkey isn't
  in our corpus and the signature isn't forgeable; per the writeup the attacker
  clears this gate by **replaying their own device's legitimately-signed misecids
  prefix**. We model that already-cleared gate — the bug is the *length
  decoupling*, not a signature forgery.
- **`xiaomi_malloc @0x214f0` → a redzoned chunk** (same asan bookkeeping as the
  emulator's own `malloc`) so the over-long `memmove` trips the asan
  out-of-bound-write detector at `chunk+0x800` instead of silently smashing heap.

## Run

```sh
# inside the ta_emu docker image, cwd /srv/emulator (see ../../run-docker.sh)
./fuzz.sh ../mitee/harness/idmanager_double_fetch \
          ../mitee/harness/idmanager_double_fetch/in/seed_s26_1
```

Env overrides: `S26_LEN1` (gate length, default `0x80`),
`S26_LEN2` (use length, default `0x2000`).

## Observed result (deterministic)

```
[Idmanager:INFO][TA_InvokeCommandEntryPoint:38]idmanager handle cmd: 0002
[S26-1] ecc_verify() -> 0  (signature gate modelled as cleared)
[S26-1] read#2 @0x204f0: interposing len2=0x2000 (gate saw len1=0x80)
[S26-1] xiaomi_malloc(0x800) -> 0x70001020  (redzoned)
[S26-1] >>> memmove(dest=0x70001020, src=0xbbbbe028, len=0x2000) into a 0x800 chunk
memmove 0x2000 from 0xbbbbe028 to 0x70001020
=================[lr: 0x555555576018] [memmove] out-of-bound write on address 0x70001020, size 0x2000!!
   CPU Context:  x0=0x70001020 (dest chunk)   x1=0xbbbbe028 (=p0+8 src)   x2=0x2000 (len2)
[+] Error occurred: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)   # CRASH_PC sentinel
```

`lr = 0x555555576018 = ta_base + 0x22018` = the return site of `bl memmove @0x22014`
— the exact sink S26-1 names. `src = 0xbbbbe028 = p0.buf + 8`. The `0x2000`-byte
copy into the `0x800` chunk overruns by `0x1800` → asan OOB-write → `CRASH_PC`
(`UC_ERR_FETCH_UNMAPPED` is this emulator's normal "bug detected" signal — a PC
redirect to the crash sentinel, *not* a harness error).

Saved evidence: `scripts/exploit/fuzz_crashes/idmanager_s26_1_double_fetch/`.

## Scope / honest caveat (unchanged from the S26 writeup §3)

This reproduces the **in-TA double-fetch primitive** (verified-length ≠
copied-length → heap overflow) under the standard GP shared-memory threat model.
It does **not** prove REE *concurrent writability* of the input VMO — that
requires the MiTEE TA-manager / MTK TEE driver, which is **not in the corpus**.
MiTEE maps the input MEMREF read-only in place with no copy-in
(`map_shm_buffer_internal`, the VMO handle moved in via `zx_channel_read` from
`fuchsia.ta.manager`) and sibling TAs defensively whole-message copy-in — both
consistent with a REE-mutable VMO — but the manager-side page provenance is the
sole residual. So S26-1 remains "double-fetch dynamically demonstrated; race
window assumed per the standard model."
