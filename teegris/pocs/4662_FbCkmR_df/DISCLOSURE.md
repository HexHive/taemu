
An out-of-bounds read vulnerability exists in a Trusted Application (UUID: 00000000-0000-0000-0000-4662436b6d52) running on Samsung's TEEGRIS, caused by inconsistent values obtained through a double-fetch problem.

## Device Information

The build fingerprint of the device is `TODO`

The sha1 of the TA is `0fa082207a6cbc294983ed95f5dcba2a679056ec`

## Detailed Vulnerability Analysis

Attackers in the REE can invoke `TA_InvokeCommandEntryPoint` through `TEEC_InvokeCommand`. By supplying `TEE_Param params[4]` together with an appropriate `uint32_t paramTypes`, the execution flow is directed to `tz_process_command`. Note that the attackers place the shared memory buffer between the REE and the TEE in `params` by assigning `TEEC_MEMREF_*` to `param_types`.

In the following, we focus only on `*params` and `params[1]`.

```C
void TA_InvokeCommandEntryPoint
               (undefined8 param_1,undefined8 param_2,int param_types,undefined8 *params)
{
  int iVar2;
  undefined8 uVar3;
  
  if (param_types == 0x65) {
    iVar2 = TEES_IsREESharedMemory(1,*params,params[1]);
    if (iVar2 == 0) {
      iVar2 = TEES_IsREESharedMemory(3,params[2],params[3]);
      if (iVar2 == 0) {
        tz_process_command(*params,params[1],params[2],params[3]);
        uVar3 = 0;
        goto LAB_0010b670;
      }
      uVar3 = 0x2f;
    }
    else {
      uVar3 = 0x28;
    }
    // ...
  }
}
```

In `tz_process_command`, `params_validate` performs the length check of `param_idx0` using the first read of `*(uint *)(param_idx0 + 4)` as buffer bounds. Later, when `get_msg_length` is called, the same field is read again and stored in `len_plus8`, which is then passed as the second argument to `buggy_func_to_crash`. 


```C
undefined8
tz_process_command(undefined8 param_idx0,undefined8 param_idx1,undefined8 param_idx2,
                  undefined4 param_idx3)
{
  uint uVar1;
  int len_plus8;
  undefined8 uVar2;
  char *pcVar6;
  char *pcVar7;
  long lVar8;
  undefined8 local_78;
  
  local_78 = 0;
  uVar1 = hvm_list(&local_78,0x20,5);
  if ((uVar1 & 0xff) == 1) {
    uVar1 = params_validate(param_idx0,param_idx1);
    if (uVar1 == 0) {
      len_plus8 = get_msg_length(param_idx0); /* less than 0x80000 */
      if (len_plus8 == 0) {
        uVar2 = log_print(3,0,"tz_process_command",0x71);
        pcVar6 = "%s%s(%u) should not be %u, goto %s";
        pcVar7 = "in_len";
        goto LAB_0010f098;
      }
      
      lVar8 = buggy_func_to_crash(param_idx0,len_plus8,1);
    }
  }
  // ...
  LAB_0010f098:
      snprintf(&DAT_00139114,0x100,pcVar7,uVar3,pcVar8,uVar10,0,"prepare_return");
```

Inside `buggy_func_to_crash`, this second fetched value is used as the size parameter of `memcpy()`. Because the value is fetched twice without guaranteeing consistency, an attacker may modify `*(uint *)(param_idx0 + 4)` between the check and the use, resulting in a TOCTOU race that can trigger an out-of-bounds read in the following code.


```C
char * buggy_func_to_crash(void *param_1,uint param_2,char param_3)

{
  char *pcVar2;
  void *__dest;
  char *pcVar3;
  
  pcVar2 = (char *)OPENSSL_malloc(0x10);
  if (pcVar2 == (char *)0x0) {
    pcVar3 = "bl";
LAB_0010c9ac:
    FUN_0010b9f4(0,pcVar3,0,&DAT_00105a8c);
    OPENSSL_free(pcVar2);
    pcVar2 = (char *)0x0;
  }
  else {
    *pcVar2 = param_3;
    if (param_3 == '\0') {
      *(void **)(pcVar2 + 8) = param_1;
    }
    else {
      __dest = (void *)OPENSSL_malloc((ulong)param_2); 
      *(void **)(pcVar2 + 8) = __dest;
      if (__dest == (void *)0x0) {
        pcVar3 = "bl->data";
        goto LAB_0010c9ac;
      }
      // param_2, which is len_plus8, exceeds the bounds of param_1.
      memcpy(__dest,param_1,(ulong)param_2);  /* crash here. oob read to param1 */
    }
    *(uint *)(pcVar2 + 4) = param_2;
  }
    return pcVar2;
}

```

For more details, we take a closer look at `params_validate` and `get_msg_length`. The core logic of `params_validate` is implemented in `FUN_0010ec70`. This function takes `*params` and `params[1]` as `param_1` and `param_2`, respectively. The layout of `param_1` is roughly as shown in lines 10–11. The value of `*(uint *)(param_1 + 4)` indicates the total length of the `data` starting at offset 8. This `data` is composed of smaller units, whose layout is shown in lines 22–25.

Also, `param_2` here serves as the size that defines the boundary of the entire shared memory region `param_1`, which adheres to the definition of the memref of `TEE_Param`. 


```C
long params_validate(void)
{
  char cVar2;
  cVar2 = FUN_0010ec70();
  return (ulong)(cVar2 == '\0') << 1;
}

1  void FUN_0010ec70(long param_1,uint param_2)
2  {
3    int iVar1;
4    ulong next_unit_offset;
5    ulong idx;
6    uint len;
7    char type;
8    uint unit_len;
9
10      /* offset 0x00  : 4 bytes，smth
11          offset 0x04 : 4 bytes，len of data
12          offset 0x08 : data (units) */
13    if ((param_1 != 0) && (7 < param_2)) {
14      len = *(uint *)(param_1 + 4); // first fetch
15      /* length check */
16      if ((len < 0x7fff9) && ((len <= param_2 - 8 && (3 < len)))) {
17        idx = 0;
18        unit_len = 0;
19        next_unit_offset = 4;
20        do {
21          type = *(char *)(param_1 + 8 + idx + 3);
22          /* offset +0..+2  : smth
23              offset +3     : type = 0x02
24              offset +4..+7 : data_len (uint)
25              offset +8..   : data[data_len] */
26          if (type == '\x02') {
27            idx = (next_unit_offset & 0xffffffff) + 4;
28            if (len < idx) {
29              return;
30            }
31            unit_len = *(uint *)(param_1 + 8 + (next_unit_offset & 0xffffffff));
32            iVar1 = (int)idx;
33              /* check on unit's length */
34            if (len - iVar1 < unit_len) {
35              return;
36            }
37            unit_len = unit_len + iVar1;
38          }
39          else {
40              /* offset +0..+2  : smth
41                  offset +3     : type = 0x01
42                  offset +4..+7 : fixed field */
43            if (type != '\x01') {
44              return;
45            }
46            unit_len = unit_len + 8;
47          }
48          idx = (ulong)unit_len;
49          next_unit_offset = idx + 4;
50        } while (next_unit_offset <= len);
51      }
52    }
53    return;
54  }
```

For the sake of simplicity, we set the data length (at offset 4) in `param_1` to **0** and provide no meaningful `data` bytes. Meanwhile, `param_2` is set to a value no smaller than 7, such as **0x10**. As a result, the program does not enter the entire if branch starting at line 16 and instead returns directly. In other words, this allows us to satisfy the length check while making `param_1` appear to be an almost empty yet valid buffer.


Subsequently, at the same memory position, the inner data length (at offset 4 of `param_1`) is retrieved once again in `get_msg_length`, incremented by 8, and used as the return value, as shown below. We rename it as `len_plus8` accordingly in `tz_process_command`.


```C
1  uint get_msg_length(long param_1)
2  {
3    undefined8 uVar2;
4    uint uVar3;
5    if (param_1 != 0) {
6      uVar3 = *(int *)(param_1 + 4) + 8;  // second fetch
7      if (uVar3 < 0x80001) goto LAB_0010ebd0;
8      uVar2 = log_print(3,0,"get_msg_length",0x246);
9      snprintf(&DAT_00139114,0x100,"%smsg len(%u) is bigger than the max len(%u)",uVar2,(ulong)uVar3,
10               0x80000);
11      printf("%s\n",&DAT_00139114);
12      perror2kmsg(&DAT_00139114);
13    }
14    uVar3 = 0;
15  LAB_0010ebd0:
16    return uVar3;
17  }
```

At this point, the attacker only needs to modify the inner data length before the second fetch at line 6 to a value smaller than 0x80001 (0x8002 in the POC) so that it passes the check at line 7. As a result, subsequent uses of `param_1`, e.g., `memcpy()` in `buggy_func_to_crash`, can lead to an out-of-bounds read to a completely invalid buffer.


## Screenshots for Validity


### Source code of the POC


```C
[=]     [TA_CreateEntryPoint] start @0x55555555f6b4
[=]     [TA_CreateEntryPoint] reach end @0x55555555f704
[=]     [TA_OpenSessionEntryPoint] start @0x55555555f75c
[=]     snprintf: len: 0x100 "b'FK [WRN] (TA_OpenSessionEntryPoint:80) \x00'" written to 0x55555558d014, lr: 0x55555555f9a8
[=]     snprintf: len: 0x100 "b'FK [WRN] (TA_OpenSessionEntryPoint:80) Start fk version 0.1.00\x00'" written to 0x55555558d114, lr: 0x55555555f7c0
[=]     printf: FK [WRN] (TA_OpenSessionEntryPoint:80) Start fk version 0.1.00

[=]     open called for /dev/kmsg returning fd 5
[=]     strlen 0x55555558d114: 62
[=]     [TA_OpenSessionEntryPoint] reach end @0x55555555f80c
[=]     TEEC_RegisterSharedMemory 0x13337 0x70ba73f5f000 0x1000
[=]     TEEC_RegisterSharedMemory 0x13338 0x70ba73f1d000 0x1000
[=]     [TA_InvokeCommandEntryPoint] start @0x55555555f554
[=]     TEES_IsREESharedMemory returning 0
[=]     TEES_IsREESharedMemory returning 0
[=]     OPENSSL_malloc: allocated 0x10 at 0xaaaaa020
[=]     redzone hook 0xaaaaa000
[=]     redzone hook 0xaaaaa030
[=]     OPENSSL_malloc: allocated 0x28 at 0xaaaab020
[=]     redzone hook 0xaaaab000
[=]     redzone hook 0xaaaab048
[=]     memset 0x28 bytes of 0x0 fill to 0xaaaab020
[=]     OPENSSL_malloc: allocated 0x10 at 0xaaaac020
[=]     redzone hook 0xaaaac000
[=]     redzone hook 0xaaaac030
[=]     OPENSSL_malloc: allocated 0x800a at 0xaaaad020
[=]     redzone hook 0xaaaad000
[=]     redzone hook 0xaaab502a
[=]     memcpy 0x800a from 0xbbbbe000 to 0xaaaad020
[x]     =================[lr: 0x555555560988] [memcpy] memory corruption detected!!
[x]     CPU Context:
[x]     x0      : 0xaaaad020
[x]     x1      : 0xbbbbe000
[x]     x2      : 0x800a
[x]     x3      : 0x1000
[x]     x4      : 0x555555557ad4
[x]     x5      : 0x555555558963
[x]     x6      : 0x50
[x]     x7      : 0x0
[x]     x8      : 0x595e9fbd94fda700
[x]     x9      : 0x595e9fbd94fda700
[x]     x10     : 0x595e9fbd94fda700
[x]     x11     : 0x7fff8
[x]     x12     : 0x0
[x]     x13     : 0x0
[x]     x14     : 0x0
[x]     x15     : 0x0
[x]     x16     : 0x555555587ff0
[x]     x17     : 0x99999290
[x]     x18     : 0x0
[x]     x19     : 0xaaaac020
[x]     x20     : 0x800a
[x]     x21     : 0xbbbbe000
[x]     x22     : 0x800a
[x]     x23     : 0x800a
[x]     x24     : 0x10
[x]     x25     : 0x0
[x]     x26     : 0x0
[x]     x27     : 0x0
[x]     x28     : 0x0
[x]     x29     : 0x8000002ddd30
[x]     x30     : 0x555555560988
[x]     sp      : 0x8000002ddd20
[x]     pc      : 0xdeadbeef
[x]     lr      : 0x555555560988
[x]     cpacr_el1       : 0x300000
[x]     pstate  : 0x3c5
[x]     PC = 0x00000000deadbeef (unreachable)

[x]     Memory map:
[x]     Start            End              Perm    Label                                     Image
[x]     00000099999000 - 0000009999a000   rwx     dl_resolve
[x]     000000aaaaa000 - 000000aaaab000   rw-     malloc_chunk
[x]     000000aaaab000 - 000000aaaac000   rw-     malloc_chunk
[x]     000000aaaac000 - 000000aaaad000   rw-     malloc_chunk
[x]     000000aaaad000 - 000000aaab6000   rw-     malloc_chunk
[x]     000000bbbbb000 - 000000bbbbc000   rw-     session_id
[x]     000000bbbbc000 - 000000bbbbd000   rw-     session_context
[x]     000000bbbbd000 - 000000bbbbe000   rw-     TEE_Params
[x]     000000bbbbe000 - 000000bbbbf000   rw-     shared_memory_0
[x]     000000bbbbf000 - 000000bbbc0000   rw-     shared_memory_1
[x]     000000eeeee000 - 000000eeef0000   rwx     [hook_mem]
[x]     00555555554000 - 0055555555f000   r--     00000000-0000-0000-0000-4662436b6d52.ta   /srv/emulator/rootfs/00000000-0000-0000-0000-4662436b6d52.ta
[x]     0055555555f000 - 00555555587000   r-x     00000000-0000-0000-0000-4662436b6d52.ta   /srv/emulator/rootfs/00000000-0000-0000-0000-4662436b6d52.ta
[x]     00555555587000 - 00555555589000   rw-     00000000-0000-0000-0000-4662436b6d52.ta   /srv/emulator/rootfs/00000000-0000-0000-0000-4662436b6d52.ta
[x]     0055555558a000 - 0055555558e000   rw-     00000000-0000-0000-0000-4662436b6d52.ta   /srv/emulator/rootfs/00000000-0000-0000-0000-4662436b6d52.ta
[x]     007ffff7dd5000 - 007ffff7de1000   r-x     libtzld.so                                /srv/emulator/rootfs/lib64/libtzld.so
[x]     007ffff7df1000 - 007ffff7df2000   rw-     libtzld.so                                /srv/emulator/rootfs/lib64/libtzld.so
[x]     007ffffffde000 - 008000002de000   rwx     [stack]
```

For reference, the dependent files for the PoC are attached here.
- `tee_client_api.h`: Open-sourced in the OPTEE repo
- `tee.h`: Open-sourced in the OPTEE repo
- `repro.h`: Contains basic utilities specific to this PoC, primarily handling parameter initialization, TEE Client API invocation, and character-related operations.
- `libteecli.so`: Can be found at the device path ./vendor/lib64/libteecli.so.



### Vulnerability Reproduction

1. preacquisition
2. interaction



