Command line used to find this crash:

afl-fuzz -t 5000 -i /srv/mitee/harness/3d08_fuzz/df_fuzz/run:id:d94cbaa36a76fb920453314b09494bcd_326484619057931876090719276077193848688/in -o /srv/mitee/harness/3d08_fuzz/df_fuzz/run:id:d94cbaa36a76fb920453314b09494bcd_326484619057931876090719276077193848688/out -m none -U -- python3 -m emulate --df_fuzz @@ --fuzz_harness /srv/mitee/harness/3d08_fuzz/harness.py --df_seed /srv/mitee/harness/3d08_fuzz/in/suspicious_inputs_replay/run:id:d94cbaa36a76fb920453314b09494bcd --df_reg_hash 326484619057931876090719276077193848688 rootfs/3d08821c-33a6-11e6-a1fa089e01c83aa2.ta

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

