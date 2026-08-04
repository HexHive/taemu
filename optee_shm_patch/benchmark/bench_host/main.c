/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Benchmark host for the OP-TEE shared-memory mitigation.
 *
 * Usage: optee_shm_bench <which> <cmd> <size> <iters> [warmup] [work]
 *   which : 0 = baseline TA (unpatched libutee)
 *           1 = mitigated TA (patched libutee)
 *   cmd   : 0 = COPIED command (not opted in -> copy path under mitigation)
 *           1 = SHARED command (opted in    -> direct path under mitigation)
 *   size  : memref buffer size in bytes
 *   iters : measured invocations
 *   warmup: warmup invocations (default 200)
 *   work  : per-call TA workload iterations (default 0)
 *
 * Prints one CSV line:
 *   which,cmd,size,iters,work,total_ns,mean_ns,min_ns,median_ns
 */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tee_client_api.h>

static const TEEC_UUID uuid_base = {
	0x11111111, 0x1111, 0x1111,
	{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }
};
static const TEEC_UUID uuid_mitig = {
	0x22222222, 0x2222, 0x2222,
	{ 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 }
};

static int cmp_u64(const void *a, const void *b)
{
	unsigned long long x = *(const unsigned long long *)a;
	unsigned long long y = *(const unsigned long long *)b;

	return (x > y) - (x < y);
}

static unsigned long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_SharedMemory shm;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t eo;
	const TEEC_UUID *uuid;
	int which, cmd;
	size_t size;
	unsigned long iters, warmup = 200, work = 0;
	unsigned long i;
	unsigned long long *samples;
	unsigned long long total = 0, mn = ~0ULL, t0, t1;

	if (argc < 5) {
		fprintf(stderr,
			"usage: %s <which0|1> <cmd0|1> <size> <iters> "
			"[warmup] [work]\n", argv[0]);
		return 2;
	}
	which = atoi(argv[1]);
	cmd = atoi(argv[2]);
	size = strtoul(argv[3], NULL, 0);
	iters = strtoul(argv[4], NULL, 0);
	if (argc > 5)
		warmup = strtoul(argv[5], NULL, 0);
	if (argc > 6)
		work = strtoul(argv[6], NULL, 0);

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

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = size;
	op.params[1].value.a = work;
	op.params[1].value.b = 0;

	for (i = 0; i < warmup; i++) {
		res = TEEC_InvokeCommand(&sess, cmd, &op, &eo);
		if (res != TEEC_SUCCESS)
			errx(1, "InvokeCommand(warmup): 0x%x origin 0x%x",
			     res, eo);
	}

	samples = calloc(iters, sizeof(*samples));
	if (!samples)
		errx(1, "calloc");

	for (i = 0; i < iters; i++) {
		t0 = now_ns();
		res = TEEC_InvokeCommand(&sess, cmd, &op, &eo);
		t1 = now_ns();
		if (res != TEEC_SUCCESS)
			errx(1, "InvokeCommand: 0x%x origin 0x%x", res, eo);
		samples[i] = t1 - t0;
		total += samples[i];
		if (samples[i] < mn)
			mn = samples[i];
	}

	qsort(samples, iters, sizeof(*samples), cmp_u64);

	printf("RESULT,%d,%d,%zu,%lu,%lu,%llu,%llu,%llu,%llu\n",
	       which, cmd, size, iters, work, total, total / iters, mn,
	       samples[iters / 2]);
	fflush(stdout);

	free(samples);
	TEEC_ReleaseSharedMemory(&shm);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
