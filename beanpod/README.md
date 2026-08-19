# Beanpod (and Kinibi)

TA corpus, harnesses and PoCs for Beanpod. See [`../README.md`](../README.md)
§1 for what each subdirectory holds and §5 for how the experiments use them.

**Kinibi TAs live here too.** They are emulated with the Beanpod runtime, so
their binaries are in `tas/` and they are fuzzed through the harnesses below;
in Table I they are counted once for Kinibi and once for Beanpod. Which TA
belongs to which TEE is recorded in `ae/data/dataset.json` (`beanpod` and
`kinibi` entries).

## Provenance

| | |
|---|---|
| firmware | `moon_global_images_OS2.0.201.0.VNTMIXM_15.0` |
| `tas/df1edda8627911e980ae507b9d9a7e7d.ta` | from an Infinix handset (the Kinibi PayTrigger TA of Listing 7) |

Table I: 11 GlobalPlatform Beanpod TAs, 5 of which operate directly on shared
memory; 6 Kinibi TAs, 3 of which do.

## Contents

    tas/                 11 Beanpod + 6 Kinibi TAs, with the .json entry-point
                         offsets and bbs/ CFGs
    harness/0801_fuzz    08010203…  ifaa-key      (Table II, oob read)
    harness/0801_poc     08010203…  ifaa-key, harness variant used for the PoC
    harness/655a_fuzz    655a4b46…
    harness/8aaa_fuzz    8aaaf201…
    harness/abcd_fuzz    abcd270e…
    harness/df1e_fuzz    df1edda8…  PayTrigger
    pocs/0801_df_oob     Table II: ifaa-key out-of-bounds read
    pocs/df1e_test       Table III: the Kinibi zero-copy probe (§6 of ../README.md)
