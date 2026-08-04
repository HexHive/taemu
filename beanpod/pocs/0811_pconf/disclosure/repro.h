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

void load_functions()
{
    void *handle;
    char *error;
    handle = dlopen("/vendor/lib64/libTEECommon.so", RTLD_LAZY);
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

void* allocate_param(int mem_size, int type, TEEC_Context* ctx, TEEC_SharedMemory* p)
{
    if (mem_size == 0)
        return NULL;
    
    void* mem_area = malloc(mem_size);
    memset(mem_area, 0x0, mem_size);

    p->buffer = mem_area;
    p->size = mem_size;
    p->flags = type;
    TEEC_RegisterSharedMemory_impl(ctx, p);

    return mem_area;
}

void release_param(TEEC_SharedMemory* p)
{
    void* mem_area = p->buffer;
    TEEC_ReleaseSharedMemory_impl(p);
    free(mem_area);
}

void hex2bytes(char* in, unsigned char* out){
    for (size_t count = 0; count < 32; count++) {
        sscanf(in, "%2hhx", &out[count]);
        in += 2;
    }
    return;
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
