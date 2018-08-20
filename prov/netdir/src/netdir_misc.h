/*
* Copyright (c) 2015-2016 Intel Corporation, Inc.  All rights reserved.
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* BSD license below:
*
*     Redistribution and use in source and binary forms, with or
*     without modification, are permitted provided that the following
*     conditions are met:
*
*      - Redistributions of source code must retain the above
*        copyright notice, this list of conditions and the following
*        disclaimer.
*
*      - Redistributions in binary form must reproduce the above
*        copyright notice, this list of conditions and the following
*        disclaimer in the documentation and/or other materials
*        provided with the distribution.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
* BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
* ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#ifndef _FI_NETDIR_MISC_H_
#define _FI_NETDIR_MISC_H_

#include "rdma/fabric.h"
#include "rdma/fi_eq.h"
#include "rdma/fi_domain.h"
#include "rdma/fi_endpoint.h"

typedef struct nd_queue_item {
	struct nd_queue_item	*next;
} nd_queue_item_t;

__declspec(align(16)) struct nd_queue_queue {
	union {
		struct {
			nd_queue_item_t	*head;
			nd_queue_item_t	*tail;
		};
		volatile LONG64 exchange[2];
	};
};

typedef struct nd_queue_queue nd_queue_t;

static inline void ofi_nd_queue_push(nd_queue_t *queue,
				     nd_queue_item_t *item)
{
	assert(queue);

	item->next = 0;
	BOOLEAN success;

	struct {
		nd_queue_item_t *head;
		nd_queue_item_t *tail;
	} src;

	do {
		src.head = queue->head;
		src.tail = queue->tail;

		LONG64 head = (LONG64)(src.head ? src.head : item);
		LONG64 tail = (LONG64)item;
		__declspec(align(16)) LONG64 compare[2] = {(LONG64)src.head, (LONG64)src.tail};
		success = InterlockedCompareExchange128(
			queue->exchange, tail, head, compare);
	} while (!success);

	if (src.tail) {
		src.tail->next = item;
		WakeByAddressAll(&src.tail->next);
	}
}

typedef struct nd_eq_event {
	OVERLAPPED ov;
	uint32_t eq_event;
	union {
		struct fi_eq_entry	operation;
		/* fi_eq_cm_entry could not be used here because it has
		   incomplete size */
		/*struct fi_eq_cm_entry	connection;*/
		struct fi_eq_err_entry	error;
	};
	void *data;
	size_t len;
	int is_custom;
} nd_eq_event_t;


typedef struct nd_eq {
	struct fid_eq fid;
	volatile LONG count;
	HANDLE iocp;
	HANDLE err;
	CRITICAL_SECTION lock;
	nd_eq_event_t *peek;
} nd_eq_t;

typedef struct nd_cq {
	struct fid_cq fid;
} nd_cq_t;

typedef struct nd_domain {
	struct fid_domain fid;
	IND2Adapter *adapter;
	IND2CompletionQueue *cq;
	ND2_ADAPTER_INFO ainfo;
	HANDLE adapter_file;
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} addr;
} nd_domain_t;

typedef struct nd_ep {
	struct fid_ep fid;
	struct fi_info *info;
	struct nd_eq *eq;

	nd_cq_t *cq_send;
	nd_cq_t *cq_recv;

	uint64_t send_flags;
	uint64_t recv_flags;
	nd_domain_t *domain;
	IND2Connector *connector;
	IND2QueuePair *qp;

	nd_queue_t prepost;
} nd_ep_t;

typedef struct nd_connreq {
	struct fid handle;
	IND2Connector *connector;
} nd_connreq_t;

#endif
