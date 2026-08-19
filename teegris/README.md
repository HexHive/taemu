# TEEGris

TA corpus, harnesses and PoCs for Samsung's TEEGris. See
[`../README.md`](../README.md) §1 for what each subdirectory holds and §5 for
how the experiments use them.

## Provenance

| | |
|---|---|
| firmware | `SM-S921B_SFR_S921BXXS9BYH2_fac` (Galaxy S24) |
| `pocs/s10_5345_SECFR` | targets the SEC_FR TA of a Galaxy S10 (`SM-G973F`) |

Table I: 33 GlobalPlatform TAs, 9 of which operate directly on shared memory.

## Contents

    tas/                         33 TAs, with .json entry-point offsets and bbs/ CFGs
    harness/000000534b4d_fuzz    …534b4d
    harness/000048444350_fuzz    …48444350  HDCP
    harness/0000534b504d_fuzz    …534b504d  SKPM
    harness/4662436b6d52_fuzz    …4662436b6d52  FbSkmR (Table II, oob read)
    harness/474154454b45_cmd7e   …474154454b45  GATEKEEPER, command 0x7e
    harness/657365636f6d_fuzz    …657365636f6d
    harness/secfr_fuzz           …5345435f4652  SEC_FR
    harness/semese_fuzz          …53454d655345  SEMeSE
    harness/sspproxy_fuzz        …534258505859  SSP proxy
    pocs/4662_FbCkmR_df          Table II: FbSkmR out-of-bounds read
    pocs/s10_5345_SECFR          Table III: the TEEGris zero-copy probe — a third
                                 thread watches the registered buffer while
                                 TEEC_InvokeCommand is blocked (§6 of ../README.md)
