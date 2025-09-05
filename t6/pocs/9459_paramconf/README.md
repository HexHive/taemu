# Parameter confusion in the 9459b61a-02d3-4d1e-b68be94397e7ca8c T6 TA

The TA doesn't check the parameter types and assumes param[0] is a memref. This directly leads to a crash where the first int is read from the buffer.

```
undefined4 TA_InvokeCommandEntryPoint(void *p1,int cmd,int ptypes,void *params)
{
  int* buf1;
  if (log_lvl < 2) {
    ta_logging?(1,"fsfp-tee-entry-tk","(%d) \'%s\' enter.",0x83,"TA_InvokeCommandEntryPoint");
    buf1 = params[0].memref.buffer;
  }
  else {
    buf1 = params[0].memref.buffer;
  }
  if (buf1 == (uint *)0x0) {
    uVar2 = perror(0xffffffea,cmd);
    ta_logging?(3,"fsfp-tee-entry-tk","error at %s(%d): \'%s\'.","TA_InvokeCommandEntryPoint",0x89,
                uVar2);
    return 0xffff0006;
  }
  int actual_cmd = buf1[0]; // buf1 is dereferenced without ensuring it is actually a buffer, not a value
``` 

This vulnerability may be weaponized to achieve code execution as the TA from the normal world and is a critical vulnerability for TAs (https://www.usenix.org/system/files/usenixsecurity24-busch-globalconfusion.pdf).

## Reproduce

You need a rooted Android phone running the T6 tee with the vulnerable TA.

compile the poc and upload to the phone (adjust ndk path):
```
ANDROID_NDK=~/Android/Sdk/ndk/29.0.13599879 make 
```

## Remediation 

Ensure that the first value of ptypes is `TEEC_MEMREF*`.
