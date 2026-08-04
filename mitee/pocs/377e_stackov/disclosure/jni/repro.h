#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SIZE 0x1000

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


void load_functions()
{
    void *handle;
    char *error;
    handle = dlopen("/vendor/lib64/libteecli.so", RTLD_LAZY);
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
}

void* allocate_param_mem(TEEC_Context* context, int mem_size)
{
    if (mem_size == 0)
        return NULL;
    uint32_t shm_size = (mem_size % PAGE_SIZE == 0)?(mem_size):(mem_size - (mem_size % PAGE_SIZE) + PAGE_SIZE);
    void* mem_area = mmap(NULL, shm_size,
                      PROT_READ | PROT_WRITE,   // RW permissions
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0); 
    memset(mem_area, 0x0, shm_size);
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
