/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef __WORKER_H__
#define __WORKER_H__

#include <pthread.h>

#include "msgbuf-struct.h"

/*
 * How long to wait for messages before giving up, in milliseconds
 */
#define NETCONS_RTO 200

struct hashtable;
struct timerlist;

struct ncrx_worker {
	struct msg_buf *queue_head;
	struct msg_buf *queue_tail;

	pthread_t id;
	pthread_condattr_t condattr;
	pthread_cond_t cond;
	pthread_mutex_t queuelock;
	int nr_queued;

	struct hashtable *ht;
	struct timerlist *tlist;
	struct timespec wake;

	unsigned int gc_age_ms;
	unsigned int gc_int_ms;
	uint64_t lastgc;

	uint64_t processed;
	uint64_t hosts_seen;
	int thread_nr;

	/*
	 * Flags
	 */
	unsigned stop:1;
};

void *ncrx_worker_thread(void *arg);

#endif
