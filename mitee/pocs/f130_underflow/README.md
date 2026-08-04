# Parameter Buffer underflow in the f13010e0-2ae1-11e5-896a0002a5d5c51d mitee trusted application

## Details

In command id 0x105 of the TA, if a buffer (`params[0].memref`) with size < 4 is passed, this leads to a parameter buffer underflow.

```
int out = commnd_dispatch(params[0].memref.buf,params[0].memref.size + -4);
char* oob = (char *)(params[0].memref.buf + params[0].memref.size - 4); // points behind params[0].memref.buf if the size is < 4
*oob = (char)out;
```

This will always write 0xf6 somewhere behind the parameter buffer.

## Impact

Denial of service, a CA can crash the trusted application

## Reproduce

We reproduced the poc on the redmi note 15 pro (lapis_images_OS2.0.202.0.VPPCNXM)

compile and run the poc:
```
ANDROID_NDK=$(path to android ndk) make 
adb shell
su
```

