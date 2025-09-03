# Param buffer oob read a734eed9-d6a1-4244-aa507c99719e7b7f mitee trusted application

The `gf_sz_factory_test_cmd_entry` unconditionally reads an integer at offset 0x13630 (handlin case 0x1d), if the param buffer is smaller this leads to an oob read.

There's another case where the input is read form `0xa4880` (in the test_cmd_entry function).

## Impact

A normal world attacker able to interact with `/dev/teei0` can crash the trusted application or use this to get a memory leak.

