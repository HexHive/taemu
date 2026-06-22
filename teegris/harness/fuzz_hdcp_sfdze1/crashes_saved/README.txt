Command line used to find this crash:

afl-fuzz -V 90 -t 5000 -i /srv/teegris/harness/fuzz_hdcp_sfdze1/in -o /srv/teegris/harness/fuzz_hdcp_sfdze1/out -m none -U -- python3 -m emulate --fuzz @@ --fuzz_harness /srv/teegris/harness/fuzz_hdcp_sfdze1/harness.py rootfs/00000000-0000-0000-0000-000048444350.ta

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

