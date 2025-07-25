/* printer.c: Very simple example C netconsd module
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <msgbuf-struct.h>
#include <ncrx-struct.h>

int netconsd_output_init(int nr_workers)
{
	printf("From init hook: %d worker threads", nr_workers);
	return 0;
}

void netconsd_output_exit(void)
{
	puts("From exit hook");
}

/*
 * This is the actual function called by netconsd.
 */
void netconsd_output_handler(int t, struct in6_addr *src, struct msg_buf *buf,
		struct ncrx_msg *msg)
{
	char addr[INET6_ADDRSTRLEN] = {0};

	inet_ntop(AF_INET6, src, addr, INET6_ADDRSTRLEN);
	if (!msg)
		printf("%40s: %s\n", addr, buf->buf);
	else
		printf("%40s: %s S%06" PRIu64 " T%014" PRIu64 " F%d/L%d %s%s%s%s%s\n", addr,
			msg->version, msg->seq, msg->ts_usec, msg->facility, msg->level,
			msg->cont_start ? "[CONT START] " : "",
			msg->cont ? "[CONT] " : "",
			msg->oos ? "[OOS] ": "",
			msg->seq_reset ? "[SEQ RESET] " : "",
			msg->text);
}
