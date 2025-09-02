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
   

	unsigned char ___mitee_harness_9811_fuzz_out_default_crashes_id_000013_sig_06_src_000348_000345_time_1249605_execs_94925_op_splice_rep_6[] = {
	  0x8, 0x00, 0x00, 0x00, 0xf9, 0x30, 0x1a, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0xff, 0xdc, 0xfe, 0x7e, 0x7f, 0xff, 0x57, 0x56, 0x10, 0x00,
	  0x00, 0x47, 0x00, 0x00, 0x1c, 0x01, 0x00, 0x01, 0x08, 0x20, 0x00, 0x10,
	  0x0a, 0x00, 0x56, 0x11, 0xff, 0xf6, 0x30, 0x1a, 0x00, 0x00
	};
	unsigned int ___mitee_harness_9811_fuzz_out_default_crashes_id_000013_sig_06_src_000348_000345_time_1249605_execs_94925_op_splice_rep_6_len = 45;

 
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    
	printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1; 
    op.params[0].tmpref.size =  ___mitee_harness_9811_fuzz_out_default_crashes_id_000013_sig_06_src_000348_000345_time_1249605_execs_94925_op_splice_rep_6_len; 
    op.params[1].tmpref.buffer = mem_area2; 
    op.params[1].tmpref.size =  0x1000; 

	memcpy(mem_area1, ___mitee_harness_9811_fuzz_out_default_crashes_id_000013_sig_06_src_000348_000345_time_1249605_execs_94925_op_splice_rep_6, ___mitee_harness_9811_fuzz_out_default_crashes_id_000013_sig_06_src_000348_000345_time_1249605_execs_94925_op_splice_rep_6_len);
    
	TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x44, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);

}


int main(int argc, char **argv)
{
    char* ta = "9811c1f6-47e3-5cea-ae6ef62ba433c4fd";
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
