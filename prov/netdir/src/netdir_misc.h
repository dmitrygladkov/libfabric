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

#include <ndspi.h>

#include "ofi_list.h"

#include "rdma/fi_eq.h"
#include "rdma/fi_endpoint.h"

typedef struct nd_eq_event {
	OVERLAPPED		ov;
	int			is_custom;
	uint32_t		eq_event;
	union {
		struct fi_eq_entry	operation;
		/* fi_eq_cm_entry could not be used here because it has
		   incomplete size */
		/*struct fi_eq_cm_entry	connection;*/
		struct fi_eq_err_entry	error;
	};

	/* connection data */
	void			*data;
	size_t			len;
} nd_eq_event_t;


typedef struct nd_eq {
	struct fid_eq		fid;
	size_t			cnum;
	HANDLE			iocp;
	HANDLE			err;
	volatile LONG		count; /* total number of available events,
				          including peek, queued & errors */
	nd_eq_event_t	*peek;

	CRITICAL_SECTION	lock;
	void*			errdata;
} nd_eq_t;

typedef struct nd_pep {
	struct fid_pep	fid;
	struct fi_info	*info;

	nd_eq_t	*eq;

	IND2Adapter	*adapter;
	IND2Listener	*listener;

	HANDLE		adapter_file;
} nd_pep_t;

typedef void(*nd_free_event_t)(struct nd_event_base* base);
typedef void(*nd_event_t)(struct nd_event_base* base, DWORD bytes);
typedef void(*nd_err_t)(struct nd_event_base* base, DWORD bytes, DWORD err);

typedef struct nd_event_base {
	OVERLAPPED		ov;

	nd_free_event_t		free;
	nd_event_t		event_cb;
	nd_err_t		err_cb;
} nd_event_base_t;

void CALLBACK domain_io_cb(DWORD err, DWORD bytes, LPOVERLAPPED ov);

typedef struct nd_domain {
	struct fid_domain		fid;
	struct nd_eq			*eq;
	struct fi_info			*info;

	uint64_t			eq_flags;

	IND2Adapter			*adapter;
	IND2CompletionQueue		*cq;

	nd_event_base_t			ov;

	HANDLE				adapter_file;
	ND2_ADAPTER_INFO		ainfo;

	LONG64				msg_cnt;

	LONG				cq_canceled;

	union {
		struct sockaddr		addr;
		struct sockaddr_in	addr4;
		struct sockaddr_in6	addr6;
	} addr;
	struct dlist_entry		ep_list;
} nd_domain_t;

typedef struct nd_mr {
	struct fid_mr		fid;

	IND2MemoryRegion	*mr;
	IND2MemoryWindow	*wnd;
} nd_mr_t;

typedef struct nd_cq {
	struct fid_cq		fid;
	enum fi_cq_format	format;

	HANDLE			iocp;
	HANDLE			err;
	volatile LONG		count; /* total number of available events,
					  including queued & errors */
} nd_cq_t;

typedef struct nd_connreq {
	struct fid	handle;
	IND2Connector	*connector;
} nd_connreq_t;

typedef struct nd_flow_block_flags {
	unsigned is_send_blocked : 1;
} nd_flow_block_flags;

typedef struct nd_cntr {
	struct fid_cntr		fid;
	volatile LONG64		counter;
	volatile LONG64		err;
} nd_cntr_t;

typedef struct nd_queue_item {
	struct nd_queue_item	*next;
} nd_queue_item_t;

__declspec(align(16)) typedef struct nd_queue_queue {
	union {
		struct {
			nd_queue_item_t	*head;
			nd_queue_item_t	*tail;
		};
		volatile LONG64 exchange[2];
	};
} nd_queue_queue_t;

typedef struct nd_srx {
	struct fid_ep		fid;
	struct fi_rx_attr	attr;
	IND2SharedReceiveQueue	*srx;
	struct nd_domain	*domain;
	struct dlist_entry	received;
	CRITICAL_SECTION	prepost_lock;
	nd_queue_queue_t	prepost;
} nd_srx_t;

typedef struct nd_ep {
	struct fid_ep			fid;
	struct fi_info			*info;

	nd_domain_t		*domain;
	nd_eq_t			*eq;
	nd_srx_t			*srx;

	nd_cq_t			*cq_send;
	nd_cq_t			*cq_recv;

	uint64_t			send_flags;
	uint64_t			recv_flags;

	nd_cntr_t			*cntr_send;
	nd_cntr_t			*cntr_recv;
	nd_cntr_t			*cntr_read;
	nd_cntr_t			*cntr_write;

	IND2Connector			*connector;
	IND2QueuePair			*qp;

/*
	struct nd_unexpected		unexpected;
*/
	nd_queue_queue_t		prepost;
	nd_queue_queue_t		internal_prepost;

	nd_event_base_t			disconnect_ov;

	CRITICAL_SECTION		prepost_lock;
	LONG				shutdown;
	LONG				connected;

	struct dlist_entry		entry;
	struct {
		nd_flow_block_flags	flags;
		size_t			used_counter;
		CRITICAL_SECTION	send_lock;
	} send_op;
	nd_queue_queue_t		send_queue;
} nd_ep_t;

void ofi_nd_ep_progress(nd_ep_t *ep);

static inline void ofi_nd_eq_push(nd_eq_t *eq, nd_eq_event_t *ev)
{
	assert(eq);
	assert(ev);

	assert(eq->iocp);
	PostQueuedCompletionStatus(eq->iocp, 0, 0, &ev->ov);
	InterlockedIncrement(&eq->count);
	WakeByAddressAll((void*)&eq->count);
}

static inline void ofi_nd_eq_push_err(nd_eq_t *eq, nd_eq_event_t *ev)
{
	assert(eq);
	assert(ev);

	assert(eq->err);
	PostQueuedCompletionStatus(eq->err, 0, 0, &ev->ov);
	InterlockedIncrement(&eq->count);
	WakeByAddressAll((void*)&eq->count);
}

typedef enum ofi_nd_cq_state {
	NORMAL_STATE		= 0,
	LARGE_MSG_RECV_REQ	= 1,
	LARGE_MSG_WAIT_ACK	= 2,
	MAX_STATE		= 3
} ofi_nd_cq_state_t;

typedef enum ofi_nd_cq_event {
	NORMAL_EVENT		= 0,
	LARGE_MSG_REQ		= 1,
	LARGE_MSG_ACK		= 2,
	MAX_EVENT		= 3
} ofi_nd_cq_event_t;

typedef struct nd_flow_cntrl_flags {
	unsigned req_ack : 1;
	unsigned ack : 1;
	unsigned empty : 1;
} nd_flow_cntrl_flags_t;

typedef struct nd_sge {
	ND2_SGE	entries[256];
	ULONG	count;
} nd_sge_t;

struct nd_cq_entry;

typedef struct nd_send_entry {
	nd_queue_item_t	queue_item;
	nd_sge_t			*sge;
	struct nd_cq_entry		*cq_entry;
	struct nd_cq_entry		*prepost_entry;
	nd_ep_t		*ep;
} nd_send_entry_t;

typedef struct nd_cq_entry {
	nd_event_base_t		base;
	nd_domain_t	*domain;
	struct nd_msgprefix	*prefix;
	struct nd_inlinebuf	*inline_buf;
	struct nd_notifybuf	*notify_buf;
	struct iovec		iov[ND_MSG_IOV_LIMIT];
	size_t			iov_cnt;

	/* used for RMA operations */
	size_t			mr_count;
	IND2MemoryRegion	*mr[ND_MSG_IOV_LIMIT];
	ND2_RESULT		result;

	uint64_t		flags;
	uint64_t		seq;
	void*			buf;
	size_t			len;
	uint64_t		data;
	nd_queue_item_t	queue_item;
	int			completed;
	void*			context;

	struct {
		struct nd_msg_location	*locations;
		/* != 0 only in case of large message
		 * receiving via RMA read */
		size_t			count;
	} rma_location;
	struct {
		/* these parameters are specified in
		 * parent's CQ entry to wait until all
		 * read/write operation will be completed */
		size_t comp_count;
		size_t total_count;

		CRITICAL_SECTION comp_lock;
	} wait_completion;
	struct nd_cq_entry	*aux_entry;

	ofi_nd_cq_state_t		state;
	ofi_nd_cq_event_t		event;
	nd_flow_cntrl_flags_t	flow_cntrl_flags;
	nd_send_entry_t		*send_entry;
} nd_cq_entry_t;


#endif
