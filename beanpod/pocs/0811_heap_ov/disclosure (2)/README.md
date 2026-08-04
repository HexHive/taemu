# 4 byte heap buffer overflow in the keyinstall (08110000000000000000000000000000) trusted application

## Affected Version

The TA is from the Redmi 13 (OS2.0.201.0.VNTMIXM_15.0).  (newest firmware)

## Details

command id 0x1 in the TA triggers the `query_drmkey_impl` function, which parses the user's input buffer, iterates over the keyblocks and writes 
the read keyIds to the output buffer.

The output buffer is allocated in `TA_InvokeCommandEntryPoint` like this: 
```
output_buffer = TEE_Malloc(params[1].size, 0);
```

The output buffer and `params[1].size` is then passed to the `query_drmkey_impl` function.

The function reads from the input buffer in a loop and for each iteration the `keyid` is written to the output buffer. 
There is a check prevent oob writes in the output buffer, however it allows an oob write of 4 bytes.

```
  if (out_buf_size < iteration_index << 2) { //out_buf_size == params[1].size
    msee_ta_printf_va("[KI_TA] ERROR:");
    msee_ta_printf_va("Corruption error: Exceeded keytype size");
    msee_ta_printf_va("\n");
    return 0xffff0000;
  }
  *(int *)(out_buf + iteration_index * 4) = keyid;
```

Note that if the `iteration_index*4` is exactly equal to `out_buf_size` then the check passes but the keyid will be written 
at `out_buf + out_buf_size` which leads to a heap overflow of 4 bytes out of bounds.

To fix the bug the check should be small equal: 
``` 
if (out_buf_size <= iteration_index << 2) {
```

The attached poc simply allocates a chunk of size 4 and writes to offset 4 in this chunk (oob write). 

## Reproduce

compile and run the poc on the affected phone:
```
$(Android-NDK)/29.0.13599879/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang -ggdb -O0 ta_client.c -o ta_client
adb push ta_client /data/local/tmp
adb shell
su
/data/local/tmp/ta_client
```

## Impact

Could lead to arbitrary code execution in the TEE as the TA
