Command line used to find this crash:

afl-fuzz -t 5000 -i /srv/qsee/harness/3d08_fuzz/df_fuzz/run:id:d8dbfd2292c425cd4723164bb3a521f6_167199059788120436054222057454213458674/in -o /srv/qsee/harness/3d08_fuzz/df_fuzz/run:id:d8dbfd2292c425cd4723164bb3a521f6_167199059788120436054222057454213458674/out -m none -U -- python3 -m emulate --df_fuzz @@ --fuzz_harness /srv/qsee/harness/3d08_fuzz/harness.py --df_seed /srv/qsee/harness/3d08_fuzz/in/suspicious_inputs_replay/run:id:d8dbfd2292c425cd4723164bb3a521f6 --df_reg_hash 167199059788120436054222057454213458674 rootfs/3D08821C-33A6-11E6-A1FA-089E01C83AA2.ta

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

