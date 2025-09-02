# OOB Read in the 9811c1f6-47e3-5cea-ae6ef62ba433c4fd mitee trusted application

## Details

In command id 0x44 the TA calls the `SessionSetReaderEphemeralPublicKey` function.

The relevant pseudocode, the content of buf is under attacker control:
```
SessionSetReaderEphemeralPublicKey(long param_1,long buf,ulong buf_size, ...)

{
  void* result_chunk, new_chunk;
  int result_size;
  FUN_001741a0(buf,buf + (buf_size & 0xffffffff),&result_size,&result_chunk); // result_size is the first 4 bytes in the attacker controlled buffer
    new_chunk = (void *)malloc(result_size); // allocate a chunk with that size
    memcpy(new_chunk,result_chunkk,result_size);
	...
  }
  bVar1 = FUN_001457b0(*(long *)(param_1 + 0x18) + 8,new_chunk); //oob read happens here
  ...
```

`FUN_001457b0` does a memcpy of size 0x40, copying bytes from `new_chunk` into a global. This leads to an oob read if the attacker controlled buffer sets a size < 0x40

```
FUN_001457b0(long param_1, void* param_2);
  memcpy((void *)(param_1 + 0x71),param_2,0x40);
  *(undefined8 *)(param_1 + 0xd8) = 0x40;
  return 1;
```

## Impact

could lead to a memory leak using `SessionGetEphemeralKeyPair`.

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
