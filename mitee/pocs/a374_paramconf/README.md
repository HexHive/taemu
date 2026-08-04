# Parameter confusion in the a734eed9-d6a1-4244-aa507c99719e7b7f mitee trusted application

The trusted application doesn't properly check the parameter types. The TA does check the types but if the type is not correct, the TA doesn't return but continues. 

This allows a malicious CA to pass arbitrary values as pointers. (see: https://www.usenix.org/conference/usenixsecurity24/presentation/busch-globalconfusion for more details).
When handling `command_id` 0x1000, the TA copies data from a global to the arbitrary pointer. This could be abused for an arbitrary write. 

```
TA_InvokeCommandEntryPoint(int *param_1,int command_id,int parameter_types,TEEC_Params *params)

{
  if (parameter_types != 0x537) {
    nop(1,"[gf_ta_entry] [%s] parameter type is not correct.","TA_InvokeCommandEntryPoint");
    print("[GF_TA][E][gf_ta_entry] [%s] parameter type is not correct.","TA_InvokeCommandEntryPoint"
         );
	// no return here!!
  }
  iVar1 = TEE_CheckMemoryAccessRights(7,*param_4,*(undefined4 *)(param_4 + 1)); // checks if memory is rw by TA
  if (iVar1 == 0) {
    *param_1 = *param_1 + 1;
    if (command_id == 0x1000) {
      params[0].memref.size = 0xbc;
      memmove(params[0].memref.buf,&DAT_00d0cd60, 0xbc); 
	  ..
  }
  ..
```

## Impact

A normal world attacker able to interact with `/dev/teei0` can trigger the parameter confusion can be leveraged to achieve an arbitray write primitive in command_id 0x1000.

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

