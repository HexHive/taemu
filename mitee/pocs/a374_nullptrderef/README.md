# Null pointer derefence in the a734eed9-d6a1-4244-aa507c99719e7b7f mitee trusted application

The trusted application doesn't properly check that a global is initialized. This then leads to null pointer dereferences in `cmd_entry_point`

The TA should ensure the global was initialized before dereferencing it.

## Impact

A normal world attacker able to interact with `/dev/teei0` can crash the trusted application.

## Reproduce

The TA is from the Redmi 13 (OS2.0.201.0.VNTMIXM_15.0). 
compile and run the poc:
```
$(Android-NDK)/29.0.13599879/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang -ggdb -O0 ta_client.c -o ta_client
adb push ta_client /data/local/tmp
adb shell
su
/data/local/tmp/ta_client
```

