/* SPDX-License-Identifier: BSD-2-Clause */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <bench_ta.h>

TEE_Result TA_CreateEntryPoint(void)
{
#ifdef MITIG
	/*
	 * Opt command TA_BENCH_CMD_SHARED, parameter 0, into shared memory.
	 * TA_BENCH_CMD_COPIED is intentionally left unregistered so the
	 * mitigation takes the copy-in/copy-out path for it.
	 *
	 * Same split for the two double-fetch probe commands: DF_SHARED opts
	 * in (and can therefore still be raced), DF_COPIED does not.
	 */
	bool shared[4] = { true, false, false, false };

	TEE_RegisterShm(TA_BENCH_CMD_SHARED, shared, false);
	TEE_RegisterShm(TA_BENCH_CMD_DF_SHARED, shared, false);
#endif
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt __unused,
				    TEE_Param p[4] __unused,
				    void **sess __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess __unused)
{
}

/* Prevent the workload loop from being optimised away. */
static volatile uint64_t bench_sink;

/*
 * params[0] : MEMREF_INOUT  - the shared/copied buffer (touched, not scanned)
 * params[1] : VALUE_INPUT   - .a = workload iterations (size-independent CPU work)
 *
 * The buffer work is O(1) (first/last byte) so that the only thing scaling
 * with buffer size is the mitigation's own copy. The VALUE_INPUT drives a
 * configurable, buffer-independent compute loop that simulates a TA doing real
 * work per call, so we can watch the mitigation's *percentage* overhead shrink
 * as the TA's own runtime grows.
 */
static TEE_Result bench_cmd(uint32_t pt, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				       TEE_PARAM_TYPE_VALUE_INPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	unsigned char *buf;
	size_t sz;
	uint32_t work, i;
	uint64_t acc = 0;

	if (pt != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	buf = params[0].memref.buffer;
	sz = params[0].memref.size;
	if (buf && sz) {
		buf[0]++;
		buf[sz - 1]++;
	}

	work = params[1].value.a;
	for (i = 0; i < work; i++)
		acc += (i ^ acc) * 2654435761u + 1;
	bench_sink = acc;

	return TEE_SUCCESS;
}

/*
 * Double-fetch probe.
 *
 * params[0] : MEMREF_INOUT - the shared/copied buffer, raced by the client
 * params[1] : VALUE_INOUT  - in  .a = probe iterations
 *                            out .a = iterations whose two reads disagreed
 *                            out .b = iterations executed
 *
 * Each iteration reads the same word twice with a short compute gap in
 * between - the shape of every double fetch in the paper: read a header
 * field, validate it, read it again and use it. If the client can mutate the
 * buffer between the two reads, they disagree.
 */
static TEE_Result df_probe(uint32_t pt, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				       TEE_PARAM_TYPE_VALUE_INOUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	volatile uint32_t *word;
	uint32_t iters, i, j, differ = 0, first, second;
	uint64_t acc = 0;

	if (pt != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[0].memref.buffer ||
	    params[0].memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	word = (volatile uint32_t *)params[0].memref.buffer;
	iters = params[1].value.a;

	for (i = 0; i < iters; i++) {
		first = *word;
		for (j = 0; j < TA_BENCH_DF_GAP; j++)
			acc += (j ^ first) * 2654435761u + 1;
		second = *word;
		if (first != second)
			differ++;
	}
	bench_sink = acc;

	params[1].value.a = differ;
	params[1].value.b = iters;

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess __unused, uint32_t cmd,
				      uint32_t pt, TEE_Param params[4])
{
	switch (cmd) {
	case TA_BENCH_CMD_COPIED:
	case TA_BENCH_CMD_SHARED:
		return bench_cmd(pt, params);
	case TA_BENCH_CMD_DF_COPIED:
	case TA_BENCH_CMD_DF_SHARED:
		return df_probe(pt, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
