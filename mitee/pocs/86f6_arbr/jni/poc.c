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
    void* mem_area1 = allocate_param_mem(context, 0x2000);
    void* mem_area2 = allocate_param_mem(context, 0x2000);
    
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);

	unsigned char ___mitee_harness_86f6_fuzz_out_default_crashes_id_000006_sig_06_src_000044_000032_time_1813172_execs_148525_op_splice_rep_1[] = {
	  0x03, 0x00, 0x00, 0x00, 0x7f, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00,
	  0x7f, 0x70, 0xda
	};
	unsigned int ___mitee_harness_86f6_fuzz_out_default_crashes_id_000006_sig_06_src_000044_000032_time_1813172_execs_148525_op_splice_rep_1_len = 14;

	memcpy(mem_area1, ___mitee_harness_86f6_fuzz_out_default_crashes_id_000006_sig_06_src_000044_000032_time_1813172_execs_148525_op_splice_rep_1, ___mitee_harness_86f6_fuzz_out_default_crashes_id_000006_sig_06_src_000044_000032_time_1813172_execs_148525_op_splice_rep_1_len);
 
	op.params[0].tmpref.buffer = mem_area1;  
    op.params[0].tmpref.size =  0x1008; 
    op.params[1].tmpref.buffer = mem_area2;  
    op.params[1].tmpref.size =  0x1008; 


    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x300, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
}


int main(int argc, char **argv)
{
    char* ta = "86f623f6-a299-4dfd-b560ffd3e5a62c29";
    TEEC_UUID *uuid = teegris_uuid(ta);

    TEEC_Context context;
    TEEC_Session session;
    uint32_t err_origin;
    TEEC_Result res;

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

    // write banner
    printf("[+] sending query...\n");
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
