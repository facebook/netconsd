/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include <ncrx-struct.h>

#include "msgbuf-struct.h"

#define MAXOUTS 32

int register_output_module(char *path, int nr_workers);
void destroy_output_modules(void);

void execute_output_pipeline(int thread_nr, struct in6_addr *src,
		struct msg_buf *buf, struct ncrx_msg *msg);

#endif /* __OUTPUT_H__ */
