# OP-TEE — Rust TAs (Section VI, Table IV)

The Rust trusted applications of Table IV, and the harnesses `e3_rust` runs
Exploration on. Unlike the other TEE directories this is not a corpus
extracted from phone firmware: these are **open-source** TAs, built from public
repositories. `../NOTICE` names the upstream projects and their licenses.

Section VI's point is that memory-safe languages do not remove the double
fetch: the TA still deserialises straight out of shared memory.

## Contents

    tas/               9 TAs with their .json entry-point offsets. No bbs/ —
                       the coverage figures cover Table I's TEEs only.
    harness/133a_fuzz  133af0ca…  message_passing_interface-rs  serde_json::from_slice
    harness/1755_fuzz  17556a46…  udp/tcp_client-rs             core::str::from_utf8
    harness/59db_fuzz  59db8536…  Bitcoin-Wallet-for-Trusted-OS-OPTEE
    harness/be2d_fuzz  be2dc9a0…  eth_wallet                    bincode::deserialize
    harness/ff09_fuzz  ff09aa8a…  mnist-rs                      bytemuck::cast_slice

There are no PoCs here: Table IV reports detected double fetches, not
exploitation.

Run it with:

    cd ae && ./ae.sh e3_rust

The mitigation of Section VII is unrelated to this directory; it lives in
`../optee_shm_patch/`.
