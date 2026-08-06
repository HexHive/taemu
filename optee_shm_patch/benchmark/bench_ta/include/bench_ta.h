/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BENCH_TA_H
#define BENCH_TA_H

/*
 * Two UUIDs so the baseline TA (built against the unpatched devkit) and the
 * mitigated TA (built against the patched devkit) can be installed side by
 * side and selected at runtime.
 *
 *   baseline : 11111111-1111-1111-1111-111111111111
 *   mitigated: 22222222-2222-2222-2222-222222222222
 */
#ifdef MITIG
#define TA_BENCH_UUID \
	{ 0x22222222, 0x2222, 0x2222, \
	  { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 } }
#else
#define TA_BENCH_UUID \
	{ 0x11111111, 0x1111, 0x1111, \
	  { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } }
#endif

/*
 * Command IDs. Both commands do identical trivial work on a single
 * MEMREF_INOUT buffer. Under the mitigation:
 *   - CMD_COPIED is NOT registered  -> libutee copies the buffer in/out
 *   - CMD_SHARED IS registered      -> libutee uses the shared buffer directly
 * Under the baseline TA the mitigation code does not exist, so both behave
 * identically (direct shared access).
 */
#define TA_BENCH_CMD_COPIED	0
#define TA_BENCH_CMD_SHARED	1

/*
 * Double-fetch probe commands. They read the same word of params[0] twice per
 * iteration, with a short compute gap in between, and report how often the two
 * reads disagreed while the normal world races the buffer. Same opt-in split
 * as above:
 *   - CMD_DF_COPIED is NOT registered -> libutee copies -> reads are stable
 *   - CMD_DF_SHARED IS registered     -> live shared buffer -> reads can differ
 * Under the baseline TA both are live shared buffers.
 */
#define TA_BENCH_CMD_DF_COPIED	2
#define TA_BENCH_CMD_DF_SHARED	3

/* Compute iterations between the two fetches of one probe iteration. */
#define TA_BENCH_DF_GAP		256

#endif /* BENCH_TA_H */
