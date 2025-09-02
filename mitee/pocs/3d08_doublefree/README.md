# Double Free in the 3d08821c-33a6-11e6-a1fa089e01c83aa2 mitee trusted application

## Details

In command id 0x1001 the TA calls the `sim_del` function with the attacker-controlled buffer as the first argument.

The data in the buffer is unhexlified and written to a heap buffer. This buffer is freed twice if the call to `_get_path_from_imsi` fails. This can be easily achieved since this call tries looking up a path based on the attackers input buffer.

```
ulong sim_del(void* buf)

{
  void* __ptr = (void *)unhexlify(param_1 + 8,*(undefined4 *)(param_1 + 4));
  if (*(int *)(param_1 + 4) == 0x12) {
    ret = del_imsi_index(__ptr,9);
    free(__ptr); //first free
    if (ret == 0) { //success
      __ptr_00 = (void *)_get_path_from_imsi(param_1 + 8,1); // fails here
      if (__ptr_00 == (void *)0x0) {
        printf("[%s:%s][%s:%d]get sim file path error\n","VSIMApp","ERROR","sim_del",0x57);
        free(__ptr); //second free
        return 0xfffe0001;
      }
```

## Impact

The double free may be leveraged to corrupt heap memory and achieve code execution.

## Reproduce

We reproduced the poc on the redmi note 15 pro (lapis_images_OS2.0.202.0.VPPCNXM)

compile and run the poc:
```
ANDROID_NDK=$(path to android ndk) make 
adb shell
su
```

## NOTES:

7252e2032d81671e9488af4a7a5eea37 (md5sum of crash seed)


588f8b551c646225f035f560904695cd (md5sum of a crash with a similar oob read)
