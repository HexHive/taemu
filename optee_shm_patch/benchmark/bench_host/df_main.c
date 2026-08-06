/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Double-fetch probe host for the OP-TEE shared-memory mitigation.
 *
 * Answers the functional question the latency benchmark does not: can the
 * normal world still change a memref under the TA's feet?
 *
 * A flipper thread writes alternating values into the first word of the shared
 * buffer as fast as it can while the TA reads that same word twice per probe
 * iteration. The TA reports how many iterations saw two different values.
 *
 *   baseline     (unpatched libutee)          -> races land, differ > 0
 *   mitig_shared (patched, opted in)          -> races land, differ > 0
 *   mitig_copied (patched, NOT opted in)      -> TA reads its private copy,
 *                                                differ == 0
 *
 * Usage: optee_shm_dftest <which> <cmd> <size> <iters> [rounds]
 *   which : 0 = baseline TA, 1 = mitigated TA
 *   cmd   : 2 = DF_COPIED (not opted in), 3 = DF_SHARED (opted in)
 *   size  : memref buffer size in bytes (>= 4)
 *   iters : probe iterations per invocation
 *   rounds: invocations to sum over (default 1)
 *
 * Prints one CSV line:
 *   DFRESULT,which,cmd,size,iters,rounds,differ,total_iters,flips
 */
#include <err.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

static const TEEC_UUID uuid_base = {
	0x11111111, 0x1111, 0x1111,
	{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }
};
static const TEEC_UUID uuid_mitig = {
	0x22222222, 0x2222, 0x2222,
	{ 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 }
};

#define VAL_A	0xaaaaaaaau
#define VAL_B	0x55555555u

static volatile uint32_t *g_word;
static volatile int g_stop;
static volatile unsigned long long g_flips;

static void *flipper(void *arg __attribute__((unused)))
{
	unsigned long long n = 0;

	while (!g_stop) {
		*g_word = VAL_A;
		*g_word = VAL_B;
		n += 2;
	}
	g_flips = n;
	return NULL;
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_SharedMemory shm;
	TEEC_Operation op;
	TEEC_Result res;
	pthread_t th;
	uint32_t eo;
	const TEEC_UUID *uuid;
	int which, cmd;
	size_t size;
	unsigned long iters, rounds = 1, r;
	unsigned long long differ = 0, total = 0;

	if (argc < 5) {
		fprintf(stderr, "usage: %s <which0|1> <cmd2|3> <size> <iters> "
			"[rounds]\n", argv[0]);
		return 2;
	}
	which = atoi(argv[1]);
	cmd = atoi(argv[2]);
	size = strtoul(argv[3], NULL, 0);
	iters = strtoul(argv[4], NULL, 0);
	if (argc > 5)
		rounds = strtoul(argv[5], NULL, 0);
	if (size < sizeof(uint32_t))
		errx(2, "size must be >= 4");

	uuid = which ? &uuid_mitig : &uuid_base;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "InitializeContext: 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &eo);
	if (res != TEEC_SUCCESS)
		errx(1, "OpenSession: 0x%x origin 0x%x", res, eo);

	memset(&shm, 0, sizeof(shm));
	shm.size = size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	res = TEEC_AllocateSharedMemory(&ctx, &shm);
	if (res != TEEC_SUCCESS)
		errx(1, "AllocateSharedMemory: 0x%x", res);
	memset(shm.buffer, 0, size);

	g_word = (volatile uint32_t *)shm.buffer;
	*g_word = VAL_A;

	if (pthread_create(&th, NULL, flipper, NULL))
		errx(1, "pthread_create");

	for (r = 0; r < rounds; r++) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
						 TEEC_VALUE_INOUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].memref.parent = &shm;
		op.params[0].memref.offset = 0;
		op.params[0].memref.size = size;
		op.params[1].value.a = (uint32_t)iters;
		op.params[1].value.b = 0;

		res = TEEC_InvokeCommand(&sess, cmd, &op, &eo);
		if (res != TEEC_SUCCESS)
			errx(1, "InvokeCommand: 0x%x origin 0x%x", res, eo);

		differ += op.params[1].value.a;
		total += op.params[1].value.b;
	}

	g_stop = 1;
	pthread_join(th, NULL);

	printf("DFRESULT,%d,%d,%zu,%lu,%lu,%llu,%llu,%llu\n",
	       which, cmd, size, iters, rounds, differ, total, g_flips);
	fflush(stdout);

	TEEC_ReleaseSharedMemory(&shm);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
