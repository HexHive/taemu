/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <bench_ta.h>

#define TA_UUID			TA_BENCH_UUID

/* Single-instance, multi-session, keep alive to avoid reload between invokes */
#define TA_FLAGS		(TA_FLAG_SINGLE_INSTANCE | \
				 TA_FLAG_MULTI_SESSION | \
				 TA_FLAG_INSTANCE_KEEP_ALIVE)

#define TA_STACK_SIZE		(2 * 1024)
#define TA_DATA_SIZE		(256 * 1024)

#define TA_VERSION		"1.0"
#define TA_DESCRIPTION		"SHM mitigation benchmark TA"

#endif /* USER_TA_HEADER_DEFINES_H */
