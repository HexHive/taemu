# Vulnerability writeup — DJI OP-TEE TA `e91c9402-64a0-470f-88e7-bf5d3c606b6a`

**Target:** Trusted Application `e91c9402-64a0-470f-88e7bf5d3c606b6a.elf` (DJI Mavic 3 firmware, MediaTek/OP-TEE).
Statically-linked OP-TEE TA (libutee baked in). AArch64. Image base `0x100000`.
**Attacker model:** a normal-world Client Application (CA) that can open a session to this TA and invoke commands. No secrets, no signing keys.
**Class:** unauthenticated, normal-world-triggerable memory corruption in the secure world.

All findings share **one root cause**: a family of "SSD" command handlers take a 16-bit *slot index* out of CA-controlled shared memory and use it to index two fixed **32-entry** global arrays **without any bounds check** (and, in places, re-fetch it — a double-fetch). The two arrays are:

| symbol | addr | size | element |
|--------|------|------|---------|
| `ssd_info_ptr_array` | `0x129c30` | 32 entries / `0x100` B | `void*` to a `0x6e`-byte SSD record |
| `ssd_nonce_array`    | `0x129e60` | 32 entries / `0x80` B  | `u32` per-slot challenge nonce |

Adjacent secure globals/heap that an out-of-bounds index reaches (all forward of `0x129e60`):

| addr | contents |
|------|----------|
| `0x129ee0` | 16-byte derived AES-CMAC key (secure-debug auth) |
| `0x129ef8` | `onetime_enable_flag` (one-time provisioning gate) |
| `0x129f30` | `ta_heap` — 32 KB TA heap (operation objects, transient key material, derived keys) |

---

## Command dispatch & parameter model (context)

`TA_InvokeCommandEntryPoint` (`0x1098a8`) is a `switch(cmd_id)`. The OP-TEE entry trampoline `__utee_entry` (`0x119ac4`) unmarshals the 4 GP params into a local copy before dispatch, so the *param descriptors* (types, sizes) cannot be raced. Each handler is `handler(paramTypes, params)` and — across the whole TA — validates `paramTypes == <const>`, so classic GP type-confusion (VALUE-where-MEMREF) is **not** available.

What **is** attacker-controlled and abused here:
- the **contents** of MEMREF buffers (they live in CA shared memory, re-readable/changeable at any time → double-fetch), and
- in particular a **16-bit index field read from inside a memref buffer**, used to index secure-world global arrays.

OP-TEE core guarantees memref buffers point only at CA-owned memory, so these bugs corrupt/read **secure-world internal memory** (globals/heap), not via the memref pointer itself.

---

## BUG 1 ★ — `ssd_verify` (cmd `0x27`) → `ssd_save_info_to_memory` (`0x1001ac`)
### Unauthenticated CA-controlled write-what-where

**Reachability (`case 0x27`):**
```c
if (paramTypes == 5 /* param0 = MEMREF_INPUT */ && param0.size == 0x6d) {
    void *buf = malloc(0x6d);
    int r = get_ssd_info_from_rpmb(*(u16*)(param0.buffer + 1), buf);   // name = "ssd_<idx>"
    if (r == 0) { ssd_info_verify(buf, param0.buffer);
                  ssd_save_info_to_memory(param0.buffer, status); }
    else {        /* "ssd info not available in rpmb, save to memory" */
                  ssd_save_info_to_memory(param0.buffer, 1); }         // <-- NO verification
    free(buf);
}
```
The `else` branch is taken whenever `ssd_<idx>` is **not** provisioned in RPMB — trivially true for any large `idx`. So the sink runs with **no authentication**.

**Sink (`ssd_save_info_to_memory(CA_buffer, status)`):**
```c
u32 idx = *(u16*)(CA_buffer + 1);                 // 0..0xFFFF, NEVER checked < 32
if (ssd_info_ptr_array[idx] == 0)
    ssd_info_ptr_array[idx] = malloc(0x6e);        // (A)
void *dst = memcpy(ssd_info_ptr_array[idx], CA_buffer, 0x6d);  // (B)
*(u8*)(dst + 0x6d) = status;                       // (C)
```

Two primitives, both with a **fully CA-controlled 0x6d-byte payload** (the param0 buffer):

- **(A) slot == 0** (most OOB `.bss` slots are zero): writes a fresh **heap pointer into the secure global at `0x129c30 + idx*8`**, then fills that heap buffer with attacker bytes. Net effect: plant a *known, attacker-pointed* heap pointer into an arbitrary 8-byte-aligned secure global → if that global is later dereferenced as a pointer/handle/callback by another command, control flow / data flow is redirected to attacker-controlled heap contents.
- **(B)/(C) slot != 0**: `memcpy(slot, CA_buffer, 0x6d)` then one more byte → **writes 0x6e fully attacker-controlled bytes to whatever pointer value sits at `0x129c30 + idx*8`** = write-what-where (the "where" is any non-null 8-byte value found at the CA-chosen OOB offset; the "what" is the param0 buffer).

**Severity:** highest. Unauthenticated, controlled destination *and* controlled data (no randomness, no crypto gate). Preconditions are only `paramTypes==5`, `param0.size==0x6d`, and an unprovisioned `idx`.

---

## BUG 2 — `ssd_get_challenge` (cmd `0x26`, `0x107804`)
### Unauthenticated double-fetch (TOCTTOU) → OOB write + DoS

Only gates: `paramTypes == 7` (param0 = MEMREF_INOUT), `param0.size == 0x4c`. The index is re-read from shared memory **three times**:

```asm
; fetch #1 (gate): idx1 = CA_buf[2]|CA_buf[3]<<8
ldr  x1,[&ssd_info_ptr_array, idx1, SXTW #3]   ; load slot -> must resolve to a real ssd slot
                                               ; (else falls to get_ssd_info_from_rpmb("ssd_<idx1>"))
...
; fetch #2 (write): idx2 re-read from shared mem  (independent of idx1)
add  x0,&ssd_nonce_array, idx2, LSL #2
bl   TEE_GenerateRandom                         ; write 4 bytes at nonce_array[idx2]  (idx2 UNBOUNDED)
; fetch #3 (readback): idx3 re-read -> nonce_array[idx3] copied into CA_buf[0x48]
```

**Exploit:** set `idx1` = a provisioned/valid slot (0..31) so the gate passes, then flip `param0.buffer[2..3]` to an arbitrary `idx2` from a second NW thread before fetch #2. `TEE_GenerateRandom(&ssd_nonce_array[idx2], 4)` then writes **4 bytes at `0x129e60 + idx2*4`**, forward range `0..0x3FFFC` (~256 KB) → secure-debug key (`0x129ee0`, idx2=32), `onetime_enable_flag` (`0x129ef8`), op handles, and the entire `ta_heap` (`0x129f30`).

The written value is *random* (from `TEE_GenerateRandom`), not chosen — so this is weaker than BUG 1. Still: chosen-offset 4-byte corruption of security-critical globals and heap → heap/object/pointer corruption (groomable + repeatable + a co-resident leak via fetch #3), and a trivial **unauthenticated DoS** (point `idx1` at unmapped secure memory → data abort/panic, or `idx2` to corrupt a live handle).

---

## BUGS 3–5 — `ssd_bind` (`0x28`), `ssd_unbind` (`0x29`), `ssd_bind_external` (`0x2e`)
### Same unchecked index; CMAC-gated write, but unauthenticated OOB read in the gate

These reach the array via the same `*(u16*)(param0.buffer + 2)` with no bounds check, but the corrupting writes are **behind `ssd_verify_onetime_msg`** (`0x1068a0`), which requires an SN match + a device-derived AES-CMAC over the message — not forgeable by a CA. The writes themselves are:
- `ssd_bind` / `ssd_bind_external`: `*(u8*)(ssd_info_ptr_array[idx] + 0x6d) = 0`
- `ssd_unbind`: `*(u8*)(ssd_info_ptr_array[idx] + 0x6d) = 1`

i.e. a single byte written through an OOB-loaded pointer at a CA-chosen offset — still memory corruption, but gated.

**However**, `ssd_verify_onetime_msg` performs `*(int*)&ssd_nonce_array[idx]` (the nonce comparison) **before** the CMAC check, so an **unauthenticated OOB read / data-abort** is reachable through the gate of all three commands by supplying an out-of-range `idx`.

---

## Root cause & fix

Every SSD handler:
```c
u32 idx = *(u16*)(param0.buffer + k);   // k = 1 or 2, attacker-controlled
... ssd_info_ptr_array[idx] ... ssd_nonce_array[idx] ...
```
with **no `idx < 32` bound** and **multiple independent fetches** of the same field.

**Fix:**
1. Read `idx` **once** into a local.
2. `if (idx >= 32) return TEE_ERROR_BAD_PARAMETERS;` before any array access — ideally via a single shared accessor (`ssd_slot(idx)`) used by every SSD handler.
3. Do not call `ssd_save_info_to_memory` on the unauthenticated RPMB-miss path (cmd `0x27`) — or authenticate before persisting CA data.

A single bounds-checked, single-fetched accessor eliminates the entire family (BUGS 1–5).

---

## Affected commands (summary)

| cmd | handler | auth | primitive | severity |
|-----|---------|------|-----------|----------|
| `0x27` | `ssd_save_info_to_memory` (via `ssd_verify`) | **none** | **0x6e-byte CA-controlled write-what-where** | **critical** |
| `0x26` | `ssd_get_challenge` | none | double-fetch → 4-byte random OOB write (chosen offset) + DoS | high |
| `0x28` | `ssd_bind` | CMAC | gated 1-byte OOB write; unauth OOB read in gate | medium |
| `0x2e` | `ssd_bind_external` | CMAC | gated 1-byte OOB write; unauth OOB read in gate | medium |
| `0x29` | `ssd_unbind` | CMAC | gated 1-byte OOB write; unauth OOB read in gate | medium |

Globals/functions renamed in Ghidra: `ssd_info_ptr_array`, `ssd_nonce_array`, `ssd_get_challenge`, `ssd_verify_onetime_msg`, `get_ssd_info_from_rpmb`, `ssd_save_info_to_memory`, `ssd_info_verify`, `ssd_bind`, `ssd_unbind`, `ssd_bind_external`, `pkcs12_parse`. Full per-sink notes are in plate comments at `0x1001ac` and `0x107804`.

*Scope note:* this writeup covers the SSD index family. The remaining ~30 non-SSD command handlers were not exhaustively swept for unrelated double-fetch/length bugs.
