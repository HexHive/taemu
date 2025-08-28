#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include <dlfcn.h>
#include <fcntl.h>
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
void (*TEEC_ReleaseSharedMemory_impl)(TEEC_SharedMemory*);

#if EMULATE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SERVER_PORT 1337
#define BUF_MAX_LEN 0x100
#define MAX_SHM 0x10
#define PAGE_SIZE 0x1000

static int shm_key = 0x13337;

static TEEC_SharedMemory* shm_p[MAX_SHM];

enum funcs {
    func_TEEC_InitializeContext,
    func_TEEC_OpenSession,
    func_TEEC_InvokeCommand,
    func_TEEC_CloseSession,
    func_TEEC_RegisterSharedMemory,
    func_TEEC_ReleaseSharedMemory,
    func_TEEC_FinalizeContext,
};

void emu_err(const char* msg)
{
    printf("internal err: %s\n", msg);
    exit(0);
}

/*
 * socket msg format
 *  uint8_t type;
 *  uint8_t len;    // msg should not be larger than 0x100 bytes
 *  uint8_t socket_buf[len];
*/

void socket_send(int sock_fd, enum funcs func, uint8_t len, uint8_t* content) 
{
    if (sock_fd < 0) {
        emu_err("emulator not connected...");
    }

    if (len > BUF_MAX_LEN) {
        emu_err("socket msg too large...");
    }

    uint8_t msg[0x110] = {0};
    msg[0] = (uint8_t)func;
    msg[1] = len;
    memcpy(msg + 2, content, len);

    if (send(sock_fd, msg, len+2, 0) == -1) {
        emu_err("failed to send msg");
    }

}

void socket_recv(int sock_fd, uint8_t* buf, uint8_t* len)
{
    if (sock_fd < 0) {
        emu_err("emulator not connected...");
    }

    int recved = recv(sock_fd, buf, *len, 0);
    if (recved > *len) {
        emu_err("buf too small");
    }
    *len = recved;
}



TEEC_Result TEEC_InitializeContext_emulate(const char* name, TEEC_Context* context)
{
    int sockfd, connfd;
    struct sockaddr_in servaddr;
 
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        emu_err("socket creation failed...");
    }
    memset(&servaddr, 0, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(SERVER_PORT);
 
    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        emu_err("connection with the emulator failed...");
    }
    else
        printf("connected to the emualtor\n");

    socket_send(sockfd, func_TEEC_InitializeContext, 5, (uint8_t *)"start");

    uint8_t buf[0x10] = {0};
    uint8_t ret_len = 0x10;
    socket_recv(sockfd, buf, &ret_len);
    if (ret_len != 2 || strncmp(buf, "ok", 2)) {
        emu_err("recv msg error in TEEC_InitializeContext_emulate");
    }

    context->fd = sockfd;

    return TEEC_SUCCESS;
}

TEEC_Result TEEC_OpenSession_emulate(TEEC_Context* context,
                    TEEC_Session* session,
                    const TEEC_UUID* destination,
                    uint32_t connectionMethod,
                    const void* connectionData,
                    TEEC_Operation* operation,
                    uint32_t* returnOrigin)
{
    int socket_fd = context->fd;
    if (socket_fd < 0) {
        emu_err("emulator not connected...");
    }


    if (connectionMethod != TEEC_LOGIN_PUBLIC) {
        emu_err("connection method not supported...");
    }

    // msg here
    //  uuid 
    socket_send(socket_fd, func_TEEC_OpenSession, sizeof(TEEC_UUID), (uint8_t *)destination);

    // recv msg
    //  "ok" + session_id(int)
    uint8_t buf[0x10] = {0};
    uint8_t ret_len = 0x10;
    socket_recv(socket_fd, buf, &ret_len);
    if (ret_len != 6 || strncmp(buf, "ok", 2)) {
        emu_err("session id error");
    }

    session->ctx = context;
    session->session_id = *(uint32_t *)(buf+2);

    return TEEC_SUCCESS;
}

TEEC_Result TEEC_InvokeCommand_emulate(TEEC_Session* session,
            uint32_t commandID,
            TEEC_Operation* operation,
            uint32_t* returnOrigin)
{
    int sid = session->session_id;
    int socket_fd = session->ctx->fd;
    if (socket_fd < 0) {
        emu_err("emulator not connected...");
    }

    // sync shared memory before invoke cmd, this is jsut a walkaround...
    for (int i=0; i<4; i++) {
        int t = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);
        // printf("type: %d\n", t);
        if (t >= 5 && t <= 7 ) {    // memref type
            int found = 0;
            TEEC_TempMemoryReference* tmp = (TEEC_TempMemoryReference*) &operation->params[i];
            for (int j=0; j<4; j++) {
                if (shm_p[j] != NULL && shm_p[j]->buffer == tmp->buffer) {
                    found = 1;  
                    break;
                }
            }
            if(!found){
                emu_err("memory not allocated with allocate_shm!!!");

            } 
        }  
    }

    // msg here
    //  sid
    //  commandID
    //  paramTypes
    //  params
    uint8_t msg[0x100] = {0};
    *(uint32_t *)msg = sid;
    *(uint32_t *)(msg+4) = commandID;
    *(uint32_t *)(msg+8) = operation->paramTypes;
    memcpy(msg+12, operation->params, sizeof(operation->params));
    uint8_t len = 12 + sizeof(operation->params);
    socket_send(socket_fd, func_TEEC_InvokeCommand, len, msg);

    // recv msg
    //  "ok" + p32(ret)
    uint8_t buf[0x10] = {0};
    uint8_t ret_len = 6;
    socket_recv(socket_fd, buf, &ret_len);
    if (ret_len != 6 || strncmp(buf, "ok", 2)) {
        emu_err("recv msg error in TEEC_InvokeCommand_emulate");
    }
    uint32_t ret = 0;
    memcpy(&ret, buf+2, 4);

    operation->session = session;

    return ret;
}

TEEC_Result TEEC_RegisterSharedMemory_emulate(TEEC_Context* context, TEEC_SharedMemory* p)
{
    int socket_fd = context->fd;
    if (socket_fd < 0) {
        emu_err("emulator not connected...");
    }

    int i=0;
    for (; i<4; i++) {
        if (shm_p[i] == NULL)
            break;
    }
    if (i == 4) {
        emu_err("too many shared memory...");
    }

    printf("set %d, %p\n", i, p);
    shm_p[i] = p;
    
    // setup shared mem
    uint32_t shm_size = (p->size % PAGE_SIZE == 0)?(p->size):(p->size - (p->size % PAGE_SIZE) + PAGE_SIZE);
    int shmid = shmget(shm_key, shm_size, 0666 | IPC_CREAT);
    if (shmid == -1) {
        emu_err("shmget");
    }

    void* shared_memory = shmat(shmid, NULL, 0);
    if (shared_memory == (void *)-1) {
        emu_err("shmat");
    }
    memset(shared_memory, 0, shm_size);

    p->alloced_size = shm_size;
    p->shadow_buffer = shared_memory;
    p->registered_fd = socket_fd;

    // msg here
    //  shm_key
    //  size
    //  buf
    uint8_t msg[0x100] = {0};
    uint8_t len = 16;
    memcpy(msg, &shm_key, 4);
    memcpy(msg + 4, &shm_size, 4);
    memcpy(msg + 8, &(p->buffer), 8);
    socket_send(socket_fd, func_TEEC_RegisterSharedMemory, len, msg);

    // recv msg
    //  "ok"
    uint8_t buf[0x10] = {0};
    uint8_t ret_len = 6;
    socket_recv(socket_fd, buf, &ret_len);
    if (ret_len != 2 || strncmp(buf, "ok", 2)) {
        emu_err("recv msg error in TEEC_RegisterSharedMemory_emulate");
    }
    shm_key++;

    return TEEC_SUCCESS;
}

void TEEC_ReleaseSharedMemory_emulate(TEEC_SharedMemory* p)
{
    for (int i=0; i<4; i++)
    {
        if (shm_p[i] == p)
        {
            shm_p[i] = NULL;
            if (shmdt(p->shadow_buffer) == -1) 
                emu_err("shmdt");

            int socket_fd = p->registered_fd;
            if (socket_fd < 0) {
                emu_err("emulator not connected...");
            }
            // msg here
            //  buf
            socket_send(socket_fd, func_TEEC_ReleaseSharedMemory, 8, (uint8_t *)&(p->buffer));

            // recv msg
            //  "ok"
            uint8_t buf[0x10] = {0};
            uint8_t ret_len = 6;
            socket_recv(socket_fd, buf, &ret_len);
            if (ret_len != 2 || strncmp(buf, "ok", 2)) {
                emu_err("recv msg error in TEEC_ReleaseSharedMemory_emulate");
            }
        }
    }
}

void TEEC_CloseSession_emulate(TEEC_Session* session)
{
    int socket_fd = session->ctx->fd;
    if (socket_fd < 0) {
        emu_err("emulator not connected...");
    }

    // msg here
    //  session->id
    // printf("sid: %d\n", session->session_id);
    socket_send(socket_fd, func_TEEC_CloseSession, sizeof(session->session_id), (uint8_t*)&session->session_id);

    // recv msg
    //  "ok"
    uint8_t buf[0x10] = {0};
    uint8_t ret_len = 6;
    socket_recv(socket_fd, buf, &ret_len);
    if (ret_len != 2 || strncmp(buf, "ok", 2)) {
        emu_err("recv msg error in TEEC_CloseSession_emulate");
    }
    
    session->ctx = NULL;
    session->session_id = 0;
}

void TEEC_FinalizeContext_emulate(TEEC_Context* context)
{
    int socket_fd = context->fd;
    if (socket_fd < 0) {
        emu_err("emulator not connected...");
    } 

    socket_send(socket_fd, func_TEEC_FinalizeContext, 4, (uint8_t*)"quit");
    close(socket_fd);
}

#endif


void load_functions()
{
#if EMULATE
    TEEC_InitializeContext_impl = TEEC_InitializeContext_emulate;
    TEEC_OpenSession_impl = TEEC_OpenSession_emulate;
    TEEC_InvokeCommand_impl = TEEC_InvokeCommand_emulate;
    TEEC_CloseSession_impl = TEEC_CloseSession_emulate;
    TEEC_FinalizeContext_impl = TEEC_FinalizeContext_emulate;
    TEEC_RegisterSharedMemory_impl = TEEC_RegisterSharedMemory_emulate;
    TEEC_ReleaseSharedMemory_impl = TEEC_ReleaseSharedMemory_emulate;
    return;
#else
    void *handle;
    char *error;
    handle = dlopen("/vendor/lib/libTEECommon.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Failed to dlopen the library%s\n", dlerror());
        exit(EXIT_FAILURE);
    }   
    dlerror(); // Clear any existing error
    TEEC_OpenSession_impl = dlsym(handle, "TEEC_OpenSession");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_OpenSession: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_InitializeContext_impl = dlsym(handle, "TEEC_InitializeContext");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_InitializeContext: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_InvokeCommand_impl = dlsym(handle, "TEEC_InvokeCommand");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_InvokeCommand: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_CloseSession_impl = dlsym(handle, "TEEC_CloseSession");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_CloseSession: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_FinalizeContext_impl = dlsym(handle, "TEEC_FinalizeContext");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_FinalizeContext: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_RegisterSharedMemory_impl = dlsym(handle, "TEEC_RegisterSharedMemory");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_RegisterSharedMemory: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_ReleaseSharedMemory_impl = dlsym(handle, "TEEC_ReleaseSharedMemory");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_ReleaseSharedMemory: %s\n", error);
        exit(EXIT_FAILURE);
    }

#endif
}

void* allocate_param_mem(TEEC_Context* context, int mem_size)
{
    if (mem_size == 0)
        return NULL;
    uint32_t shm_size = (mem_size % PAGE_SIZE == 0)?(mem_size):(mem_size - (mem_size % PAGE_SIZE) + PAGE_SIZE);
#if EMULATE
    int socket_fd = context->fd;
    if (socket_fd < 0) {
        emu_err("emulator not connected...");
    }
    int i=0;
    for (; i<4; i++) {
        if (shm_p[i] == NULL)
            break;
    }
    if (i == 4) {
        emu_err("too many shared memory...");
    }
    
    int shmid = shmget(shm_key, shm_size, 0666 | IPC_CREAT);
    if (shmid == -1) {
        emu_err("shmget");
    }
    void* shared_memory = shmat(shmid, NULL, 0);
    if (shared_memory == (void *)-1) {
        emu_err("shmat");
    }
    TEEC_TempMemoryReference* memref = (TEEC_TempMemoryReference*)malloc(sizeof(TEEC_TempMemoryReference));
    memref->size = mem_size;
    memref->buffer = shared_memory;
    shm_p[i] = memref;
    memset(shared_memory, 0, shm_size);

    // msg here
    //  shm_key
    //  size
    //  buf
    uint8_t msg[0x100] = {0};
    uint8_t len = 16;
    memcpy(msg, &shm_key, 4);
    memcpy(msg + 4, &shm_size, 4);
    memcpy(msg + 8, &shared_memory, 8);
    socket_send(socket_fd, func_TEEC_RegisterSharedMemory, len, msg);

    // recv msg
    //  "ok"
    uint8_t buf[0x10] = {0};
    uint8_t ret_len = 6;
    socket_recv(socket_fd, buf, &ret_len);
    if (ret_len != 2 || strncmp(buf, "ok", 2)) {
        emu_err("recv msg error in TEEC_RegisterSharedMemory_emulate");
    }

    shm_key++;
    void* mem_area = shared_memory;
#else
    void* mem_area = mmap(NULL, shm_size,
                      PROT_READ | PROT_WRITE,   // RW permissions
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0); 
    memset(mem_area, 0x0, shm_size);
#endif
    return mem_area; 
}

void release_param(TEEC_SharedMemory* p)
{
    void* mem_area = p->buffer;
    TEEC_ReleaseSharedMemory_impl(p);
    free(mem_area);
}

void teegris_hex2bytes(char* in, unsigned char* out){
    int idx = 0;
    for (size_t count = 0; count < 36; count++) {
        if(*in == '-'){
			in += 1;
			continue;
		}
        sscanf(in, "%2hhx", &out[idx]);
        in += 2;
		idx += 1;
    }
    return;
}

void hex2bytes(char* in, unsigned char* out){
    for (size_t count = 0; count < 32; count++) {
        sscanf(in, "%2hhx", &out[count]);
        in += 2;
    }
    return;
}

TEEC_UUID* beanpod_uuid(const char* ta){
    unsigned char hex_b[0x40] = {0};
    hex2bytes(ta,hex_b);
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
    return uuid;
}

TEEC_UUID* teegris_uuid(const char* ta){
    unsigned char hex_b[0x40] = {0};
    teegris_hex2bytes(ta,hex_b);
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
    return uuid;
}

void DumpHex(const void* data, size_t size, void* sa) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
        if (i % 16 == 0) {
            printf("%12p |  ", sa+i);
        }
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
