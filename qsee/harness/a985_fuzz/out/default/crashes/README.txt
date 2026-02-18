Command line used to find this crash:

afl-fuzz -t 5000 -i /srv/qsee/harness/a985_fuzz/in -o /srv/qsee/harness/a985_fuzz/out -m none -U -- python3 -m emulate --fuzz @@ --fuzz_harness /srv/qsee/harness/a985_fuzz/harness.py rootfs/A985D3EB-3B52-4D44-BE6C-628A813561E8.ta

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

