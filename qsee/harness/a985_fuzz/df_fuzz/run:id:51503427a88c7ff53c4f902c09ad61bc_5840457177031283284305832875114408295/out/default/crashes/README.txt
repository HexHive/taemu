Command line used to find this crash:

afl-fuzz -t 5000 -i /srv/qsee/harness/a985_fuzz/df_fuzz/run:id:51503427a88c7ff53c4f902c09ad61bc_5840457177031283284305832875114408295/in -o /srv/qsee/harness/a985_fuzz/df_fuzz/run:id:51503427a88c7ff53c4f902c09ad61bc_5840457177031283284305832875114408295/out -m none -U -- python3 -m emulate --df_fuzz @@ --fuzz_harness /srv/qsee/harness/a985_fuzz/harness.py --df_seed /srv/qsee/harness/a985_fuzz/in/suspicious_inputs_replay/run:id:51503427a88c7ff53c4f902c09ad61bc --df_reg_hash 5840457177031283284305832875114408295 rootfs/A985D3EB-3B52-4D44-BE6C-628A813561E8.ta

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

