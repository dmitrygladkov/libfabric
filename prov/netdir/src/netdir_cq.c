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

#ifdef _WIN32

#include "netdir.h"
#include "netdir_misc.h"
#include "netdir_log.h"

#include "rdma/fabric.h"
#include "ofi_util.h"

static struct fid ofi_nd_fid;
static struct fi_ops_cq ofi_nd_cq_ops;

static int ofi_nd_cq_close(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_CQ);
	if (fid->fclass != FI_CLASS_CQ)
		return -FI_EINVAL;

	nd_cq_t *cq = container_of(fid, nd_cq_t, fid.fid);

	if (cq->iocp && cq->iocp != INVALID_HANDLE_VALUE)
		CloseHandle(cq->iocp);
	if (cq->err && cq->err != INVALID_HANDLE_VALUE)
		CloseHandle(cq->err);

	free(cq);

	return FI_SUCCESS;
}

int ofi_nd_cq_open(struct fid_domain *pdomain, struct fi_cq_attr *attr,
		   struct fid_cq **pcq_fid, void *context)
{
	OFI_UNUSED(context);

	assert(pdomain);
	assert(pdomain->fid.fclass == FI_CLASS_DOMAIN);

	if (pdomain->fid.fclass != FI_CLASS_DOMAIN)
		return -FI_EINVAL;

	if (pdomain->fid.fclass != FI_CLASS_DOMAIN)
		return -FI_EINVAL;

	HRESULT hr;

	if (attr)
	{
		if (attr->wait_obj != FI_WAIT_NONE &&
		    attr->wait_obj != FI_WAIT_UNSPEC)
			return -FI_EBADFLAGS;
	}

	nd_cq_t *cq = (nd_cq_t*)calloc(1, sizeof(*cq));
	if (!cq)
		return -FI_ENOMEM;

	nd_cq_t def = {
		.fid = {
			.fid = ofi_nd_fid,
			.ops = &ofi_nd_cq_ops
		},
		.format = attr ? attr->format : FI_CQ_FORMAT_CONTEXT
	};

	*cq = def;

	if (cq->format == FI_CQ_FORMAT_UNSPEC)
	{
		cq->format = FI_CQ_FORMAT_CONTEXT;
		if (attr)
			attr->format = cq->format;
	}

	nd_domain_t *domain = container_of(pdomain, nd_domain_t, fid);
	assert(domain->adapter);
	assert(domain->adapter_file);

	cq->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!cq->iocp || cq->iocp == INVALID_HANDLE_VALUE)
	{
		hr = -FI_EINVAL;
		goto hr_fail;
	}

	cq->err = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!cq->err || cq->err == INVALID_HANDLE_VALUE)
	{
		hr = -FI_EINVAL;
		goto hr_fail;
	}

	*pcq_fid = &cq->fid;

	return FI_SUCCESS;

hr_fail:
	ofi_nd_cq_close(&cq->fid.fid);
	ND_LOG_WARN(FI_LOG_CQ, ofi_nd_strerror((DWORD)hr, NULL));
	return H2F(hr);
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

typedef struct nd_msgheader {
	uint64_t		data;
	ofi_nd_cq_event_t	event;
	nd_flow_cntrl_flags_t	flags;
	size_t			location_cnt;
} nd_msgheader_t;

typedef struct nd_msgprefix {
	UINT32			token;
	nd_msgheader_t	header;
} nd_msgprefix_t;

/* push call is non-blocking thread safe */
static inline void ofi_nd_queue_push(struct nd_queue_queue *queue,
				     struct nd_queue_item *item)
{
	assert(queue);

	item->next = 0;
	BOOLEAN success;

	struct {
		nd_queue_item_t *head;
		nd_queue_item_t *tail;
	} src;

	do
	{
		src.head = queue->head;
		src.tail = queue->tail;

		LONG64 head = (LONG64)(src.head ? src.head : item);
		LONG64 tail = (LONG64)item;
		__declspec(align(16)) LONG64 compare[2] = {(LONG64)src.head, (LONG64)src.tail};
		success = InterlockedCompareExchange128(
			queue->exchange, tail, head, compare);
	} while (!success);

	if (src.tail)
	{
		src.tail->next = item;
		WakeByAddressAll(&src.tail->next);
	}
}

/* pop call is NOT thread safe, it allows only one consumer, but it is
   safe to be used with push operation without locks */
static inline int ofi_nd_queue_pop(nd_queue_queue_t *queue,
				   nd_queue_item_t **item)
{
	assert(queue);
	assert(item);

	BOOLEAN success;
	struct {
		nd_queue_item_t *head;
		nd_queue_item_t *tail;
	} src;

	do
	{
		src.head = queue->head;
		src.tail = queue->tail;

		if (!src.head)
			return 0;

		/* here is potential thread race: object located at src.head
		   may be destroyed while we're waiting. that is why pop
		   operation is not thread safe */
		if (src.head != src.tail)
		{
			/* in case if head and tail are not same - ensure that
			   head->next element is not NULL */
			void *zero = NULL;
			while (!src.head->next)
			{
				WaitOnAddress(&src.head->next, &zero, sizeof(zero), INFINITE);
			}
		}

		LONG64 head = (LONG64)src.head->next;
		LONG64 tail = (LONG64)(src.head != src.tail ? src.tail : NULL);
		__declspec(align(16)) LONG64 compare[2] = {(LONG64)src.head, (LONG64)src.tail};
		success = InterlockedCompareExchange128(
			queue->exchange, tail, head, compare);
	} while (!success);

	*item = src.head;

	return (*item) != NULL;
}

/* peek call is NOT thread safe, it allows only one consumer */
static inline int ofi_nd_queue_peek(nd_queue_queue_t *queue,
				    nd_queue_item_t **item)
{
	assert(queue);
	assert(item);

	*item = queue->head;
	return (*item) != 0;
}

void ofi_nd_ep_progress(nd_ep_t *ep)
{
	HRESULT hr;
	nd_queue_item_t *qentry = NULL;
	nd_send_entry_t *send_entry = NULL;

	EnterCriticalSection(&ep->send_op.send_lock);
	while (ofi_nd_queue_peek(&ep->send_queue, &qentry) &&
		!(ep->send_op.flags.is_send_blocked))
	{
		ep->send_op.used_counter++;
		send_entry = container_of(qentry, nd_send_entry_t, queue_item);
		ofi_nd_queue_pop(&ep->send_queue, &qentry);

		if (!(ep->send_op.used_counter % gl_data.prepost_cnt)) {
			ep->send_op.flags.is_send_blocked = 1;
			ep->send_op.used_counter = 0;
			nd_msgheader_t *header = (nd_msgheader_t *)
				send_entry->sge->entries[0].Buffer;
			header->flags.req_ack = 1;
		}

		/* If there is prepost entry (it means that this SEND event
		 * expects an answer). In this case, push CQ entry to prepost
		 * queue to receive event(answer) */
		if (send_entry->prepost_entry) {
			ND_LOG_DEBUG(FI_LOG_EP_DATA, "Posted entry(state = %d) that "
				     "expects an answer from peer to which the send "
				     "event is belong\n", send_entry->prepost_entry->state);
			ofi_nd_queue_push(&ep->internal_prepost,
				&send_entry->prepost_entry->queue_item);
		}

		hr = send_entry->ep->qp->lpVtbl->Send(send_entry->ep->qp,
			send_entry->cq_entry,
			send_entry->sge->entries,
			send_entry->sge->count, 0);
		if (FAILED(hr))
			ND_LOG_WARN(FI_LOG_CQ, "Send failed from Send Queue\n");
	}
	LeaveCriticalSection(&ep->send_op.send_lock);
}

static uint64_t ofi_nd_cq_sanitize_flags(uint64_t flags)
{
	return (flags & (FI_SEND | FI_RECV | FI_RMA | FI_ATOMIC |
		FI_MSG | FI_TAGGED |
		FI_READ | FI_WRITE |
		FI_REMOTE_READ | FI_REMOTE_WRITE |
		FI_REMOTE_CQ_DATA | FI_MULTI_RECV));
}

static inline void ofi_nd_free_cq_entry(nd_cq_entry_t *entry)
{
	assert(entry);

	while (entry->mr_count) {
		entry->mr_count--;
		entry->mr[entry->mr_count]->lpVtbl->Release(entry->mr[entry->mr_count]);
	}

	/* Means that waiting of completion are used. The completion
	 * critical section must be released */
	if (entry->wait_completion.total_count != 0)
		DeleteCriticalSection(&entry->wait_completion.comp_lock);

	/* Release nested entry */
	if (entry->aux_entry)
		ofi_nd_free_cq_entry(entry->aux_entry);

	free(entry);
}

static void ofi_nd_cq_ov2buf(struct nd_cq *cq, OVERLAPPED_ENTRY *ov,
			     void* buf, ULONG count)
{
	ULONG i;
	nd_msgprefix_t *prefix;

	switch (cq->format) {
	case FI_CQ_FORMAT_CONTEXT:
		{
			struct fi_cq_entry *entry = (struct fi_cq_entry*)buf;
			for (i = 0; i < count; i++) {
				nd_cq_entry_t *cqen = container_of(ov[i].lpOverlapped, nd_cq_entry_t, base.ov);
				entry[i].op_context = cqen->context;
				ofi_nd_free_cq_entry(cqen);
			}
		}
		break;
	case FI_CQ_FORMAT_MSG:
		{
			struct fi_cq_msg_entry *entry = (struct fi_cq_msg_entry*)buf;
			for (i = 0; i < count; i++) {
				nd_cq_entry_t *cqen = container_of(ov[i].lpOverlapped, nd_cq_entry_t, base.ov);
				entry[i].op_context = cqen->context;
				entry[i].flags = ofi_nd_cq_sanitize_flags(cqen->flags);
				/* for send/receive operations there message header used,
				   and common size of transferred message is bit
				   bigger, in this case decrement transferred message
				   size by header size */
				size_t header_len = (cqen->result.RequestType == Nd2RequestTypeSend ||
						     cqen->result.RequestType == Nd2RequestTypeReceive) ?
					sizeof(prefix->header) : 0;

				entry[i].len = cqen->result.BytesTransferred - header_len;
				ofi_nd_free_cq_entry(cqen);
			}
		}
		break;
	case FI_CQ_FORMAT_DATA:
		{
			struct fi_cq_data_entry *entry = (struct fi_cq_data_entry*)buf;
			for (i = 0; i < count; i++) {
				nd_cq_entry_t *cqen = container_of(ov[i].lpOverlapped, nd_cq_entry_t, base.ov);
				entry[i].op_context = cqen->context;
				entry[i].flags = ofi_nd_cq_sanitize_flags(cqen->flags);
				size_t header_len = (cqen->result.RequestType == Nd2RequestTypeSend ||
						     cqen->result.RequestType == Nd2RequestTypeReceive) ?
					sizeof(prefix->header) : 0;

				entry[i].len = cqen->result.BytesTransferred - header_len;
				entry[i].buf = cqen->buf;
				ofi_nd_free_cq_entry(cqen);
			}
		}
		break;
	case FI_CQ_FORMAT_TAGGED:
		{
			struct fi_cq_tagged_entry *entry = (struct fi_cq_tagged_entry*)buf;
			for (i = 0; i < count; i++) {
				nd_cq_entry_t *cqen = container_of(ov[i].lpOverlapped, nd_cq_entry_t, base.ov);
				entry[i].op_context = cqen->context;
				entry[i].flags = ofi_nd_cq_sanitize_flags(cqen->flags);
				size_t header_len = (cqen->result.RequestType == Nd2RequestTypeSend ||
						     cqen->result.RequestType == Nd2RequestTypeReceive) ?
					sizeof(prefix->header) : 0;

				entry[i].len = cqen->result.BytesTransferred - header_len;
				entry[i].buf = cqen->buf;
				entry[i].tag = 0;
				ofi_nd_free_cq_entry(cqen);
			}
		}
		break;
	default:
		ND_LOG_WARN(FI_LOG_CQ, "incorrect CQ format: %d\n", cq->format);
		break;
	}
}

static ssize_t ofi_nd_cq_read(struct fid_cq *pcq, void *buf, size_t count)
{
	assert(pcq);
	assert(pcq->fid.fclass == FI_CLASS_CQ);

	if (pcq->fid.fclass != FI_CLASS_CQ)
		return -FI_EINVAL;

	nd_cq_t *cq = container_of(pcq, nd_cq_t, fid);

	ULONG cnt = (ULONG)count;
	ULONG dequeue = 0;
	ssize_t res = 0;

#define MAX_OVERLAP_ENTRIES 256
	OVERLAPPED_ENTRY _ov[MAX_OVERLAP_ENTRIES];

	if (!cq->count)
		return -FI_EAGAIN;

	if (cq->count > 0)
	{
		InterlockedDecrement(&cq->count);
		return 1;
	}

	OVERLAPPED_ENTRY *ov = (cnt <= _countof(_ov)) ?
		_ov : malloc(cnt * sizeof(*ov));

	if (!ov)
	{
		ND_LOG_WARN(FI_LOG_CQ, "failed to allocate OV\n");
		return -FI_ENOMEM;
	}

	assert(cq->iocp && cq->iocp != INVALID_HANDLE_VALUE);
	if (!GetQueuedCompletionStatusEx(cq->iocp, ov, cnt, &dequeue, 0, FALSE) ||
	    !dequeue)
	{
		res = cq->count ? -FI_EAVAIL : -FI_EAGAIN;
		goto fn_complete;
	}

	ofi_nd_cq_ov2buf(cq, ov, buf, dequeue);
	res = (ssize_t)dequeue;
	InterlockedAdd(&cq->count, -(LONG)dequeue);
	assert(cq->count >= 0);

fn_complete:
	if (ov != _ov)
		free(ov);
	return res;
}

static ssize_t ofi_nd_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
				  fi_addr_t *src_addr)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_cq_readerr(struct fid_cq *pcq, struct fi_cq_err_entry *buf,
				 uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_cq_sread(struct fid_cq *pcq, void *buf, size_t count,
			       const void *cond, int timeout)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
				   fi_addr_t *src_addr, const void *cond,
				   int timeout)
{
	return -FI_ENOSYS;
}

static const char *ofi_nd_cq_strerror(struct fid_cq *cq, int prov_errno,
				      const void *err_data, char *buf,
				      size_t len)
{
	return -FI_ENOSYS;
}

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_cq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fid ofi_nd_fid = {
	.fclass = FI_CLASS_CQ,
	.context = NULL,
	.ops = &ofi_nd_fi_ops
};

static struct fi_ops_cq ofi_nd_cq_ops = {
	.size = sizeof(ofi_nd_cq_ops),
	.read = ofi_nd_cq_read,
	.readfrom = ofi_nd_cq_readfrom,
	.readerr = ofi_nd_cq_readerr,
	.sread = ofi_nd_cq_sread,
	.sreadfrom = ofi_nd_cq_sreadfrom,
	.signal = fi_no_cq_signal,
	.strerror = ofi_nd_cq_strerror
};

#endif /* _WIN32 */

