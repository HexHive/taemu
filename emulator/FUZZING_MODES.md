# Emulator modes & flags (opt-in)

Environment-variable–gated modes added on top of the base emulator. **All
default to off**; with none set, interactive/fuzzing behavior is unchanged.
They are read in `ta_mgr.py` / `determinism.py` unless noted.

## Determinism (`TAEMU_DETERMINISM=1`)

Makes a fuzz/replay run reproducible — *same input → same execution* — which
AFL/unicornafl assume. Without it three things diverge run-to-run and produce
flaky crashes + corrupted coverage feedback:

| source | default | under determinism |
|---|---|---|
| RNG (`TEE_GenerateRandom`, key/IV gen, `os.urandom`) | real CSPRNG (`Crypto.Random`) | SHA-256 counter DRBG, reset per InvokeCommand iteration |
| clock (`TEE_GetSystemTime`/`GetREETime`, mitee `time`) | wall clock | frozen epoch |
| persistent store (`TEE_*PersistentObject`) | real files under `./emulate/files/` | in-memory dict, reset for free by the fork server |

Knobs: `TAEMU_RNG_SEED=<int>` (default 0), `TAEMU_FAKE_TIME=<int>` (default
`0x6745a3c0`), `TAEMU_MEM_STORE=1` (in-memory store only, implied by
determinism). The DRBG state is `(seed, counter)` so `fork()` copies it; the
per-iteration `determinism.reset()` (wired into the place-input path) zeroes the
counter so every child draws the identical stream.

Implementation: `emulate/determinism.py`; the in-memory store backend lives in
`gp/utils/persistent_object.py` (`MEM_STORE`, `_MemFile`, `store_listdir`).

## Multi-command stateful fuzzing (`TAEMU_MULTI_CMD=<N>`)

One AFL input drives up to **N** `InvokeCommand`s in a **single session**, so
the fuzzer can reach inter-command state-machine bugs (command A provisions a
handle/flag that command B misuses) that the default one-shot driver cannot.

The flat AFL input is framed into length-prefixed records — repeated
`[2-byte LE length L][L bytes]` — and **each record is fed to the harness's
existing `place_input_callback` as that command's input**. So existing harnesses
work unchanged; the harness still derives the command id + params from the bytes
it is handed (e.g. `cmd = input[0]`). CPU context is snapshotted at
`InvokeCommand` entry and restored before each op (clean GP-style re-entry:
fresh SP/regs), while guest memory — heap, persistent store, session — persists
across ops.

Pairs naturally with `TAEMU_DETERMINISM=1`.

Implementation: `multi_fuzz_wrapper` in `ta_mgr.start_fuzz`, driven through
`ql_afl_fuzz_custom`; framing in `_frame_multi_input`.

> **Validation status:** framing + wiring unit-tested and import-clean; the
> default single-command path is untouched. A live AFL campaign against a real
> multi-command TA (with a seed corpus using the record framing) is the
> remaining end-to-end check.

## Comparison-operand harvester / cmplog-lite (`TAEMU_CMPLOG=1`)

Coverage-guided fuzzing stalls at byte-exact gates (`memcmp(buf, MAGIC, n)`,
`strcmp(tag, "...")`, header/length checks) because mutation rarely reproduces
the expected constant. The emulator already reimplements the common compare
functions, so under this flag it harvests the operands seen in `TEE_MemCompare`
/ `memcmp` / `strcmp` / `strncmp` into an **AFL dictionary**. Run it during a
replay pass over the seed corpus, then fuzz with `afl-fuzz -x cmplog.dict`.

  TAEMU_CMPLOG=1               enable harvesting (intended for replay passes)
  TAEMU_CMPLOG_DICT=<path>     output dict (default ./cmplog.dict)

Implementation: `emulate/cmplog.py`; `record()` calls in the compare hooks.
This is the cheap 80%; full cmplog/redqueen needs the AFL++/unicornafl bump
(Tier 4.12).

## Unmodeled-API telemetry (always on)

Every hooked symbol the emulator does **not** implement falls through to a no-op
`default_func`, which can hide a real bug or fabricate an emulator-only one. The
set of stubbed symbols hit during a run is recorded and written next to the
drcov coverage on replay (`<cov>.unmodeled`), so triage can tell whether a
finding flowed through a stub. Set `TAEMU_TELEMETRY=<path>` to also dump on exit
for any run. Implementation: `emulate/telemetry.py`.

## Weaponization mode (`TAEMU_WEAPONIZE=1`)

The asan allocator page-isolates every chunk behind redzones — great for
*detecting* an overflow, but you can never overflow into an adjacent object, so
you can't develop the actual primitive. This mode is the opposite: a bump
allocator lays `TEE_Malloc` chunks **adjacently** (16-byte aligned, no redzone,
no guard page), so an overflow corrupts the neighbouring allocation just like on
device — letting you turn a known bug into an overwrite-the-next-object
primitive. Param redzones are also suppressed. Cheap wild-free / double-free
checks are kept. Use it to *weaponize* a bug asan already found, not to find
bugs. Implementation: `_weapon_alloc` / `WEAPONIZE` branches in
`gp/utils/string.py`.

## REE/secure address-space partitioning (always on)

`TEE_CheckMemoryAccessRights` honors GP's `ANY_OWNER` flag: a TA asserting
ownership (flag clear) of a buffer that is actually REE/client-shared memory now
gets `TEE_ERROR_ACCESS_DENIED`, modeling the real secure/normal-world boundary.
Previously this only worked for plain-mapped params; the redzoned param path
(default fuzzing) tagged its mapping `redzoned_param`, so REE buffers went
unrecognized. Fixed by an explicit per-emu **REE-region registry**
(`TAEMU.REE_REGIONS`, `is_ree_addr()`, populated in `params.py` for every memref
param) plus a `shared`-tagged mapping. The registry is also the foundation the
double-fetch mode builds on. (Note: this models TAs that *call* the check
correctly; catching a TA that dereferences an unvalidated REE pointer into
secure memory needs taint tracking — future work.)

## Double-fetch / TOCTOU hunt mode (`TAEMU_DOUBLE_FETCH=1`)

One of the most productive real-world TEE bug classes: the TA reads a
length/pointer from REE shared memory to **validate** it, then reads it **again**
to **use** it, and a malicious REE mutates it in between. The default fuzzer
hands the TA a static snapshot, so it can never see this. This mode installs a
read hook on every REE param buffer (the `REE_REGIONS` from Tier 2.7) that, on
the **second+ read of a 32-bit word**, rewrites it to an adversarial poison
value (`TAEMU_DF_POISON`, default `0xffffffff`). A TA that validated on read #1
and trusts read #2 then uses the poison (e.g. as a length) → OOB → asan crash.

This is a deliberate **hunt mode**: benign double-reads get poisoned too, so
findings need triage (pair with `TAEMU_DETERMINISM` for reproducibility). It
reuses the same mid-read mutation mechanism as the interactive shared-memory
sync. Implementation: `double_fetch_read_callback` in `params.py`.

> **Validation status:** poison logic (benign first read, poison second) is
> unit-tested; a live campaign against a known double-fetch TA is the e2e check.

## Known limitations

- **Thread-vs-thread concurrency is not modeled.** `pthread_*` are stubs
  (`pthread_create` logs a warning and does **not** run the thread body). Races
  between TA threads are invisible. The one race class that *is* covered is the
  REE↔TEE race on shared buffers, via the double-fetch mode above. Don't read
  green pthread stubs as race coverage.
- **No taint tracking.** See the Tier 2.7 note: we model TAs that *call*
  `TEE_CheckMemoryAccessRights` correctly, not ones that silently trust an REE
  pointer into secure memory.
