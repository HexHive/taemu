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
adb shell
su
/data/local/tmp/poc
```

The TA will crash trying to read from the arbitrary pointer:
```
dmesg | grep tee-log
[   33.104612] (2)[135:tee-log][   46.558366]: <6>(1)
[   33.104627] (2)[135:tee-log][   46.558650]: <6>(1)user data-abort at address 0xdeadbeef
[   33.104644] (2)[135:tee-log][   46.559366]: <6>(1) esr 0x92000005  ttbr0 0x30000fc2a9000   ttbr1 0xfc198000   cidr 0x0
[   33.104659] (2)[135:tee-log][   46.560415]: <6>(1) cpu #6          cpsr 0xa0000110
[   33.104674] (2)[135:tee-log][   46.561053]: <6>(1)x0  0000000000000000 x1  0000000000000001
[   33.104690] (2)[135:tee-log][   46.561796]: <6>(1)x2  0000000000000203 x3  0000000000000002
[   33.104705] (2)[135:tee-log][   46.562540]: <6>(1)x4  00000000deadbeef x5  0000000000100fe0
[   33.104720] (2)[135:tee-log][   46.563282]: <6>(1)x6  00000000002d20e8 x7  00000000002d19cc
[   33.104735] (2)[135:tee-log][   46.564024]: <6>(1)x8  0000000000100fe0 x9  ffffffffc018c890
[   33.104750] (2)[135:tee-log][   46.564764]: <6>(1)x10 fffffffffffff000 x11 00000000001ff000
[   33.104765] (2)[135:tee-log][   46.565507]: <6>(1)x12 00000000013e5154 x13 0000000000100fa8
[   33.104779] (2)[135:tee-log][   46.566251]: <6>(1)x14 0000000000293e14 x15 7d915a1787b6aaa8
[   33.104794] (2)[135:tee-log][   46.566999]: <6>(1)x16 ffffffffc0072fa0 x17 106e3b25611db555
[   33.104809] (2)[135:tee-log][   46.567747]: <6>(1)x18 ffffffffc0188e30 x19 ffffffffc01a8a60
[   33.104824] (2)[135:tee-log][   46.568495]: <6>(1)x20 0000000000000000 x21 ffffffffc0087cc0
[   33.104838] (2)[135:tee-log][   46.569242]: <6>(1)x22 0000000000000590 x23 0000000000000110
[   33.104853] (2)[135:tee-log][   46.569989]: <6>(1)x24 0000000000000000 x25 ffffffffc2396fe0
[   33.104868] (2)[135:tee-log][   46.570738]: <6>(1)x26 ffffffffc01a8e38 x27 0000000000000002
[   33.104882] (2)[135:tee-log][   46.571488]: <6>(1)x28 0000000000000000 x29 ffffffffc01a8ad0
[   33.104897] (2)[135:tee-log][   46.572237]: <6>(1)x30 ffffffffc0010970 elr 000000000028808c
[   33.104912] (2)[135:tee-log][   46.572985]: <6>(1)sp_el0 0000000000100fe0
[   33.104926] (2)[135:tee-log][   46.573526]: <6>(1)data-abort at 0xdeadbeef
[   33.104941] (2)[135:tee-log][   46.574081]: <6>(1)ESR 0x92000005 PC 0x28808c TTBR0 0x30000fc2a9000 CONTEXIDR 0x0
[   33.104957] (2)[135:tee-log][   46.575071]: <6>(1)CPUID 0x81000600 CPSR 0xa0000110 (read from SPSR)
[   33.104970] (2)[135:tee-log]
[   33.104985] (2)[135:tee-log][   46.575932]: <6>(1)Status of TA 9459b61a-02d3-4d1e-b68be94397e7ca8c (0xffffffffc018cc20)
[   33.105000] (2)[135:tee-log][   46.577000]: <6>(1)- load addr : 0x200000    ctx-idr: 3     (active)
[   33.105015] (2)[135:tee-log][   46.577840]: <6>(1)- code area : 0xffffffffc10af000 18776064
[   33.105030] (2)[135:tee-log][   46.578587]: <6>(1)frame 1: pc 0x0028808c, sp 0x00100fa8 fp 0x001ff000
[   33.105046] (2)[135:tee-log][   46.579455]: <6>(1)frame 2: pc 0x00293e14, sp 0x00100fc8 fp 0x001ff000
[   33.105061] (2)[135:tee-log][   46.580319]: <6>(1)frame 3: pc 0x00293c58, sp 0x00100fe0 fp 0x001ff000
[   33.105076] (2)[135:tee-log][   46.581184]: <6>(1)frame 4: pc 0x00000000, sp 0x00101000 fp 0x001ff000
[   33.105091] (2)[135:tee-log][   46.582117]: <6>(1)ERR KERN:tee_user_ta_enter:1384: TA panicked with code 0xdeadbeef
```

## Remediation 

Ensure that the first value of ptypes is `TEEC_MEMREF*`.
