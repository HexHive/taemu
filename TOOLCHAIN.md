# Toolchain pinning & patch rationale

The emulator only works against a specific, patched Qiling + a specific AFL++ /
unicornafl. This documents exactly what is pinned, what is *not* (and how to
harden it), the per-hunk rationale for `emulator/qiling.diff`, and a mechanical
recipe for upgrading — including the cmplog bump that Tier 1.3 deferred.

## What is pinned (Dockerfile)

| Component | Pin | Strength |
|---|---|---|
| Qiling | commit `56dd77b6608698bfe54f4bde01981a40609c9532` (branch `dev`) + `qiling.diff` | **strong** — a commit hash is content-addressed; submodules are pinned by that commit's gitlinks |
| unicornafl | the repo's `unicornafl.py` `COPY`-ed over the AFL image's copy | **strong** — content lives in this repo |
| AFL++ | image tag `aflplusplus/aflplusplus:v4.32c` | **weak** — a tag can be re-pushed; pin by digest (below) |
| bata24 gef | `dev` branch, install best-effort (`|| true`) | unpinned (non-critical: debug only) |
| drcov-merge | `git clone` HEAD | unpinned |
| pip deps | `emulator/requirements.txt` + `networkx` | pin versions in requirements.txt |

### Hardening the weak pins (does not change current behavior)
- **AFL++ by digest:** replace the tag with a digest so the base can't drift:
  `FROM aflplusplus/aflplusplus:v4.32c@sha256:<digest>` (resolve once with
  `docker buildx imagetools inspect aflplusplus/aflplusplus:v4.32c`).
- **drcov-merge / gef by commit:** add `&& git checkout <commit>` after the
  clone.
Each needs a value resolved with network access, so it's documented here rather
than guessed.

## `emulator/qiling.diff` — per-hunk rationale

All but the last hunk are in `qiling/loader/elf.py`. CLAUDE.md summarizes the
diff as "ET_REL TrustedCore TAs, ARM overlapping segments, and the function-hook
memory base"; here is the mapping.

1. **`HOOK_MEM = 0xeeeee000` (new constant).** A fixed, out-of-the-way base for
   the function-hook region, used by hunk 4. Keeps the hook page off the TA's
   real memory layout.
2. **ET_REL handling.** TrustedCore TAs ship as `ET_REL` relocatable objects
   (not `ET_EXEC`/`ET_DYN`). Stock Qiling routes `ET_REL` through
   `load_driver()` + `hook_kernel_api` (its kernel-module path), which is wrong
   for a TA. The patch instead loads at `load_address = 0` and bumps the stack
   by `0x3000`, so `tc_load()` (emulate/custom/tc_loader.py) can place segments
   itself. (This is the "why is the TC TA ET_REL????" hunk.)
3. **ARM (32-bit) overlapping segments.** Qiling unifies "overlapping" load
   segments (same page, different perms) only for `ARM64`; the patch extends the
   same handling to 32-bit `ARM`, which several beanpod/t6 TAs need or they fail
   to map.
4. **Function-hook memory base.** `FunctionHook(...)` is constructed with
   `HOOK_MEM` instead of the real `mem_end`, so the PLT/GOT-redirect sentinel
   page (`ql_resolve_mem = 0x99999000` in emulator_no_loader.py) lives at a
   stable address independent of the TA's size.
5. **`qiling/log.py` (cosmetic).** Adds a commented-out `StreamHandler`
   alternative next to the `raise TypeError` for unexpected log-device types;
   behavior is unchanged. Safe to drop on a rebase.

## Upgrade recipe (mechanical)

1. Pick the new Qiling commit; update the hash in the Dockerfile.
2. `git apply ../qiling.diff` — if it fails, re-apply the 5 hunks above by hand
   (each is small and the rationale is here), then refresh `qiling.diff` with
   `git diff`.
3. Rebuild; smoke-test boot of one TA per TEE (`run.sh`) and one fuzz/replay.
4. The `.json` validator (`TAEMU` `validate_metadata`) will flag entry-point
   address drift loudly if a loader change moves the base.

### cmplog bump (deferred from Tier 1.3)
Tier 1.3 shipped a comparison-operand *harvester* (`emulate/cmplog.py`) that
needs no toolchain change. Full cmplog/redqueen needs an AFL++/unicornafl that
exposes the cmplog tables to the unicorn harness:
1. Bump the `aflplusplus/aflplusplus` base to a tag with unicorn cmplog support
   and re-pin by digest.
2. Refresh the vendored `unicornafl.py` from that image (re-apply the local
   override — diff it against the image copy first; the `# WTFFFFFFFFF` COPY in
   the Dockerfile is that override).
3. Enable `AFL_LLVM_CMPLOG`/the unicorn equivalent in `fuzz.sh` and verify the
   forkserver still starts.
