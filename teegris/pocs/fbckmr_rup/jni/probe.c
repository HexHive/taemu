/* cmd_id -> handler-name mapping probe for FbCkmR (SFDZE1). Sends ids 0..11 with a
 * minimal [cmd][L=0] payload; the dispatcher logs "CMD_FK_<NAME>" at tz_process_command:124. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tee_client_api.h"
#include "repro.h"
#include <dlfcn.h>
#define BUFSZ 4096
static inline void put_u32(uint8_t*p,uint32_t v){memcpy(p,&v,4);}
void cleanup_shm(){
#if EMULATE
 system("ipcrm -M 0x13337 2>/dev/null");system("ipcrm -M 0x13338 2>/dev/null");
 system("ipcrm -M 0x13339 2>/dev/null");system("ipcrm -M 0x1333a 2>/dev/null");
#endif
}
int main(){
 char* ta="00000000-0000-0000-0000-4662436b6d52"; TEEC_UUID*uuid=teegris_uuid(ta);
 uint32_t eo; TEEC_Result res; TEEC_Context ctx; TEEC_Session ses; TEEC_Operation op;
 cleanup_shm(); load_functions();
 if(TEEC_InitializeContext_impl(NULL,&ctx)!=TEEC_SUCCESS){printf("ctx fail\n");return 1;}
 if(TEEC_OpenSession_impl(&ctx,&ses,uuid,TEEC_LOGIN_PUBLIC,NULL,NULL,&eo)!=TEEC_SUCCESS){printf("sess fail\n");return 1;}
 printf("[probe] session opened\n");
 uint8_t*in=(uint8_t*)allocate_param_mem(&ctx,BUFSZ); uint8_t*out=(uint8_t*)allocate_param_mem(&ctx,BUFSZ);
 for(uint32_t c=0;c<=11;c++){
   memset(in,0,BUFSZ); memset(out,0,BUFSZ);
   put_u32(in+0,c); put_u32(in+4,0);
   memset(&op,0,sizeof(op));
   op.paramTypes=TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE,TEEC_NONE);
   op.params[0].tmpref.buffer=in; op.params[0].tmpref.size=BUFSZ;
   op.params[1].tmpref.buffer=out;op.params[1].tmpref.size=BUFSZ;
   res=TEEC_InvokeCommand_impl(&ses,c,&op,&eo);
   printf("[probe] cmd_id=%u rc=0x%x\n",c,res);
 }
 TEEC_CloseSession_impl(&ses); TEEC_FinalizeContext_impl(&ctx); return 0;
}
