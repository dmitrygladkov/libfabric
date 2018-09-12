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

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include "netdir.h"
#include "netdir_ov.h"
#include "netdir_cq.h"
#include "netdir_log.h"
#include "netdir_iface.h"
#include "netdir_unexp.h"

#include "rdma/fabric.h"
#include "rdma/fi_endpoint.h"

#include "ofi.h"
#include "ofi_util.h"

static ssize_t ofi_nd_ep_recv(struct fid_ep *ep, void *buf, size_t len,
			      void *desc, fi_addr_t src_addr, void *context);
static ssize_t ofi_nd_ep_send(struct fid_ep *ep, const void *buf, size_t len,
			      void *desc, fi_addr_t src_addr, void *context);
static ssize_t ofi_nd_ep_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
				 uint64_t flags);
static ssize_t ofi_nd_ep_recvv(struct fid_ep *ep_fid, const struct iovec *iov,
			       void **desc, size_t count, fi_addr_t src_addr,
			       void *context);
static ssize_t ofi_nd_ep_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
				 uint64_t flags);
static ssize_t ofi_nd_ep_sendv(struct fid_ep *ep_fid, const struct iovec *iov,
			       void **desc, size_t count, fi_addr_t dest_addr,
			       void *context);
static ssize_t ofi_nd_ep_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
				fi_addr_t dest_addr);
static ssize_t ofi_nd_ep_senddata(struct fid_ep *ep, const void *buf, size_t len,
				  void *desc, uint64_t data, fi_addr_t dest_addr,
				  void *context);
ssize_t ofi_nd_ep_injectdata(struct fid_ep *ep, const void *buf, size_t len,
			     uint64_t data, fi_addr_t dest_addr);

struct fi_ops_msg ofi_nd_ep_msg = {
	.size = sizeof(ofi_nd_ep_msg),
	.recv = ofi_nd_ep_recv,
	.recvv = ofi_nd_ep_recvv,
	.recvmsg = ofi_nd_ep_recvmsg,
	.send = ofi_nd_ep_send,
	.sendv = ofi_nd_ep_sendv,
	.sendmsg = ofi_nd_ep_sendmsg,
	.inject = ofi_nd_ep_inject,
	.senddata = ofi_nd_ep_senddata,
	.injectdata = ofi_nd_ep_injectdata
};

static int ofi_nd_ep_sendmsg_inline(struct nd_ep *ep,
				    struct nd_cq_entry *entry,
				    const struct fi_msg *msg,
				    size_t len)
{
	int res;
	size_t i;

	nd_flow_cntrl_flags flow_control_flags = {
		.req_ack = 0,
		.ack = 0,
		.empty = 0
	};

	struct nd_msgheader header_def = {
		.data = entry->data,
		.event = NORMAL_EVENT,
		.flags = flow_control_flags,
		.location_cnt = 0
	};
	entry->prefix->header = header_def;
	entry->event = NORMAL_EVENT;
	entry->flow_cntrl_flags = flow_control_flags;


	nd_sge *sge_entry = (nd_sge*)malloc(sizeof(*sge_entry));
	if (!sge_entry) {
		ND_LOG_WARN(FI_LOG_EP_DATA, "SGE entry buffer can't be allocated");
		res = -FI_ENOMEM;
		goto fn_fail_1;
	}
	memset(sge_entry, 0, sizeof(*sge_entry));

	if (entry->flags & FI_INJECT) {
		if (len) {
			entry->inline_buf = (struct nd_inlinebuf*)malloc(sizeof(*(entry->inline_buf)));
			if (!entry->inline_buf) {
				res = -FI_ENOMEM;
				goto fn_fail_2;
			}

			char *buf = (char*)entry->inline_buf->buffer;
			for (i = 0; i < msg->iov_count; i++) {
				memcpy(buf, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
				buf += msg->msg_iov[i].iov_len;
			}
		}

		ND2_SGE sge[2] = {
			{
				.Buffer = &entry->prefix->header,
				.BufferLength = (ULONG)sizeof(entry->prefix->header),
				.MemoryRegionToken = entry->prefix->token
			},
			{
				.Buffer = len ? entry->inline_buf->buffer : 0,
				.BufferLength = (ULONG)len,
				.MemoryRegionToken = len ? entry->inline_buf->token : 0
			}
		};

		sge_entry->count = 2;
		for (i = 0; i < sge_entry->count; i++)
			sge_entry->entries[i] = sge[i];
	}
	else {
		ND2_SGE sge = {
			.Buffer = &entry->prefix->header,
			.BufferLength = (ULONG)sizeof(entry->prefix->header),
			.MemoryRegionToken = entry->prefix->token
		};
		sge_entry->entries[0] = sge;

		for (i = 0; i < msg->iov_count; i++) {
			ND2_SGE sge_def = {
				.Buffer = msg->msg_iov[i].iov_base,
				.BufferLength = (ULONG)msg->msg_iov[i].iov_len,
				.MemoryRegionToken = (UINT32)(uintptr_t)msg->desc[i]
			};
			sge_entry->entries[i + 1] = sge_def;
		}

		sge_entry->count = (ULONG)msg->iov_count + 1;
	}

	nd_send_entry *send_entry = (nd_send_entry*)malloc(sizeof(*send_entry));
	if (!send_entry) {
		ND_LOG_WARN(FI_LOG_EP_DATA, "Send entry buffer can't be allocated");
		res = -FI_ENOMEM;
		goto fn_fail_3;
	}
	memset(send_entry, 0, sizeof(*send_entry));

	send_entry->cq_entry = entry;
	send_entry->sge = sge_entry;
	send_entry->ep = ep;

	/* Push the user's transmission request into
	 * the Send Queue for furhter handling */
	entry->send_entry = send_entry;
	ofi_nd_queue_push(&ep->send_queue, &send_entry->queue_item);

	return FI_SUCCESS;
fn_fail_3:
	if (entry->inline_buf)
		free(entry->inline_buf);
fn_fail_2:
	free(sge_entry);
fn_fail_1:
	ND_LOG_WARN(FI_LOG_EP_DATA, "The error happened during handling Send");
	return res;
}

static int ofi_nd_ep_prepare_sendmsg_large(struct nd_ep *ep,
					   struct nd_cq_entry *entry,
					   struct nd_cq_entry *wait_ack_entry,
					   const struct fi_msg *msg)
{
	size_t i;
	HRESULT hr;

	for (i = 0; i < msg->iov_count; i++) {
		uint64_t addr = (uint64_t)msg->msg_iov[i].iov_base;
		size_t len = msg->msg_iov[i].iov_len;

		/* Register MR to share data via RMA, store MR descriptor
		 * in allocated CQ entry for receiving ACK */
		hr = ep->domain->adapter->lpVtbl->CreateMemoryRegion(
			ep->domain->adapter, &IID_IND2MemoryRegion,
			ep->domain->adapter_file, (void**)&wait_ack_entry->mr[i]);
		if (FAILED(hr)) {
			ND_LOG_WARN(FI_LOG_EP_DATA, ofi_nd_strerror((DWORD)hr, NULL));
			return H2F(hr);
		}
		wait_ack_entry->mr_count++;

		hr = ofi_nd_util_register_mr(
			wait_ack_entry->mr[i], (void *)addr, len,
			ND_MR_FLAG_ALLOW_LOCAL_WRITE |
			ND_MR_FLAG_ALLOW_REMOTE_READ |
			ND_MR_FLAG_ALLOW_REMOTE_WRITE);
		struct nd_msg_location location_def = {
			.addr = addr,
			.len = len,
			.remote_mr_token = wait_ack_entry->mr[i]->lpVtbl->GetRemoteToken(
				wait_ack_entry->mr[i])
		};

		entry->notify_buf->location[i] = location_def;
	}

	return FI_SUCCESS;
}



static int ofi_nd_ep_sendmsg_large(struct nd_ep *ep,
				   struct nd_cq_entry *entry,
				   const struct fi_msg *msg)
{
	int res;
	size_t i;
	struct nd_cq_entry *wait_ack_entry;

	nd_flow_cntrl_flags flow_control_flags = {
		.req_ack = 0,
		.ack = 0,
		.empty = 0
	};

	struct nd_msgheader header_def = {
		.data = entry->data,
		.event = LARGE_MSG_REQ,
		.flags = flow_control_flags,
		.location_cnt = msg->iov_count
	};
	entry->prefix->header = header_def;
	entry->event = LARGE_MSG_REQ;
	entry->flow_cntrl_flags = flow_control_flags;

	entry->notify_buf = (struct nd_notifybuf*)malloc(sizeof(*(entry->notify_buf)));
	if (!entry->notify_buf) {
		res = -FI_ENOMEM;
		goto fn_fail_1;
	}

	/* The CQ entry to wait ACK of read completion from peer */
	wait_ack_entry = (struct nd_cq_entry*)malloc(sizeof(*wait_ack_entry));
	if (!wait_ack_entry) {
		res = -FI_ENOMEM;
		goto fn_fail_2;
	}
	memset(wait_ack_entry, 0, sizeof(*wait_ack_entry));
	wait_ack_entry->notify_buf = (struct nd_notifybuf*)malloc(sizeof(*(wait_ack_entry->notify_buf)));
	if (!wait_ack_entry->notify_buf) {
		res = -FI_ENOMEM;
		goto fn_fail_3;
	}
	wait_ack_entry->buf = wait_ack_entry->notify_buf;
	wait_ack_entry->len = sizeof(struct nd_notifybuf);
	wait_ack_entry->data = msg->data;
	wait_ack_entry->flags = FI_MSG | FI_RECV;
	wait_ack_entry->domain = ep->domain;
	wait_ack_entry->context = msg->context;
	wait_ack_entry->seq = entry->seq;
	wait_ack_entry->state = LARGE_MSG_WAIT_ACK;
	wait_ack_entry->aux_entry = entry;

	res = ofi_nd_ep_prepare_sendmsg_large(ep, entry, wait_ack_entry, msg);
	if (res)
		goto fn_fail_4;

	entry->state = LARGE_MSG_WAIT_ACK;
	ND2_SGE sge[2] = {
		{
			.Buffer = &entry->prefix->header,
			.BufferLength = (ULONG)sizeof(entry->prefix->header),
			.MemoryRegionToken = entry->prefix->token
		},
		{
			.Buffer = entry->notify_buf->location,
			.BufferLength = (ULONG)(sizeof(*entry->notify_buf->location) * msg->iov_count),
			.MemoryRegionToken = entry->notify_buf->token
		}
	};

	nd_sge *sge_entry = (nd_sge*)malloc(sizeof(*sge_entry));
	if (!sge_entry) {
		ND_LOG_WARN(FI_LOG_EP_DATA, "SGE entry buffer can't be allocated");
		res = -FI_ENOMEM;
		goto fn_fail_4;
	}
	memset(sge_entry, 0, sizeof(*sge_entry));

	sge_entry->count = 2;
	for (i = 0; i < sge_entry->count; i++)
		sge_entry->entries[i] = sge[i];

	nd_send_entry *send_entry = (nd_send_entry*)malloc(sizeof(*send_entry));
	if (!send_entry) {
		ND_LOG_WARN(FI_LOG_EP_DATA, "Send entry buffer can't be allocated");
		res = -FI_ENOMEM;
		goto fn_fail_5;
	}
	memset(send_entry, 0, sizeof(*send_entry));

	send_entry->cq_entry = entry;
	send_entry->sge = sge_entry;
	send_entry->ep = ep;
	send_entry->prepost_entry = wait_ack_entry;

	/* Push the user's transmission request into
	 * the Send Queue for furhter handling */
	entry->send_entry = send_entry;
	ofi_nd_queue_push(&ep->send_queue, &send_entry->queue_item);

	EnterCriticalSection(&ep->send_op.send_lock);

	ND2_SGE sge2 = {
		.Buffer = &entry->prefix->header,
		.BufferLength = (ULONG)sizeof(entry->prefix->header),
		.MemoryRegionToken = entry->prefix->token
	};
	HRESULT hr = ep->qp->lpVtbl->Send(ep->qp, send_entry, &sge, 2, ND_OP_FLAG_INLINE);
	LeaveCriticalSection(&ep->send_op.send_lock);
	if (FAILED(hr))
		ND_LOG_WARN(FI_LOG_CQ, "Send failed from ofi_nd_ep_sendmsg_large\n");

	return FI_SUCCESS;
fn_fail_5:
	free(sge_entry);
fn_fail_4:
	free(wait_ack_entry->notify_buf);
fn_fail_3:
	free(wait_ack_entry);
fn_fail_2:
	free(entry->notify_buf);
fn_fail_1:
	ND_LOG_WARN(FI_LOG_EP_DATA, "The error happened during handling Send");
	return res;
}

static ssize_t
ofi_nd_ep_sendmsg(struct fid_ep *pep, const struct fi_msg *msg, uint64_t flags)
{
	assert(pep->fid.fclass == FI_CLASS_EP);
	assert(msg);

	if (pep->fid.fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	size_t i;
	size_t len = 0;
	ssize_t res = FI_SUCCESS;
	struct nd_ep *ep = container_of(pep, struct nd_ep, fid);

	if (!ep->qp)
		return -FI_EOPBADSTATE;

	for (i = 0; i < msg->iov_count; i++) {
		if (msg->msg_iov[i].iov_len && !msg->msg_iov[i].iov_base)
			return -FI_EINVAL;
		len += msg->msg_iov[i].iov_len;
	}

	if ((msg->iov_count > min(ep->domain->ainfo.MaxReceiveSge, ND_MSG_IOV_LIMIT) - 1) ||
	    (len > ep->domain->info->ep_attr->max_msg_size))
		return -FI_EINVAL;

	struct nd_cq_entry *entry = (struct nd_cq_entry*)malloc(sizeof(*entry));
	if (!entry)
		return -FI_ENOMEM;
	memset(entry, 0, sizeof(*entry));

	entry->buf = (msg->iov_count == 1) ? msg->msg_iov[0].iov_base : 0;
	entry->len = len;
	entry->data = msg->data;
	entry->flags = flags | FI_MSG | FI_SEND;
	entry->domain = ep->domain;
	entry->context = msg->context;
	entry->seq = InterlockedAdd64(&ep->domain->msg_cnt, 1);

	/* since send operation can't be canceled, set NULL into
	 * the 1st byte of internal data of context */
	if (msg->context)
		ND_FI_CONTEXT(msg->context) = 0;

	entry->prefix = (struct nd_msgprefix*)malloc(sizeof(*(entry->prefix)));
	if (!entry->prefix) {
		res = -FI_ENOMEM;
		goto fn_fail_1;
	}

	res = ofi_nd_ep_sendmsg_large(ep, entry, msg);
	if (res)
		goto fn_fail_2;
	/* Let's progress Send Queue for current EP if possible */
	ofi_nd_ep_progress(ep);

	return FI_SUCCESS;
fn_fail_2:
	free(entry->prefix);
fn_fail_1:
	free(entry);
	return res;
}

static ssize_t ofi_nd_ep_inject(struct fid_ep *pep, const void *buf, size_t len,
	fi_addr_t dest_addr)
{
	struct nd_ep *ep = container_of(pep, struct nd_ep, fid);
	EnterCriticalSection(&ep->send_op.send_lock);

	ND2_SGE sge = {
		.Buffer = buf,
		.BufferLength = (ULONG)len,
		.MemoryRegionToken = NULL
	};
	HRESULT hr = ep->qp->lpVtbl->Send(ep->qp, NULL, &sge, 1, ND_OP_FLAG_INLINE);
	LeaveCriticalSection(&ep->send_op.send_lock);
	return H2F(hr);
}

ssize_t
ofi_nd_ep_injectdata(struct fid_ep *pep, const void *buf, size_t len,
		     uint64_t data, fi_addr_t dest_addr)
{
	struct iovec iov = {
		.iov_base = (void*)buf,
		.iov_len = len
	};

	struct fi_msg msg = {
		.msg_iov = &iov,
		.desc = 0,
		.iov_count = 1,
		.addr = dest_addr,
		.context = 0,
		.data = data
	};

	return ofi_nd_ep_sendmsg(pep, &msg, FI_INJECT);
}

static ssize_t ofi_nd_ep_senddata(struct fid_ep *pep, const void *buf, size_t len, void *desc,
				  uint64_t data, fi_addr_t dest_addr, void *context)
{
	struct iovec iov = {
		.iov_base = (void*)buf,
		.iov_len = len
	};

	struct fi_msg msg = {
		.msg_iov = &iov,
		.desc = &desc,
		.iov_count = 1,
		.addr = dest_addr,
		.context = context,
		.data = data
	};

	assert(pep->fid.fclass == FI_CLASS_EP);

	if (pep->fid.fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	struct nd_ep *ep = container_of(pep, struct nd_ep, fid);

	return ofi_nd_ep_sendmsg(pep, &msg, ep->info->tx_attr->op_flags);
}

static ssize_t ofi_nd_ep_send(struct fid_ep *pep, const void *buf, size_t len,
			      void *desc, fi_addr_t dest_addr, void *context)
{
	return ofi_nd_ep_senddata(pep, buf, len, desc, 0, dest_addr, context);
}

static ssize_t ofi_nd_ep_sendv(struct fid_ep *pep, const struct iovec *iov,
			       void **desc, size_t count, fi_addr_t dest_addr,
			       void *context)
{
	struct fi_msg msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.addr = dest_addr,
		.context = context,
		.data = 0
	};

	assert(pep->fid.fclass == FI_CLASS_EP);

	if (pep->fid.fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	struct nd_ep *ep = container_of(pep, struct nd_ep, fid);

	return ofi_nd_ep_sendmsg(pep, &msg, ep->info->tx_attr->op_flags);
}

static ssize_t ofi_nd_ep_recvmsg(struct fid_ep *pep, const struct fi_msg *msg,
				 uint64_t flags)
{
	assert(pep->fid.fclass == FI_CLASS_EP);
	assert(msg);

	if (pep->fid.fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	size_t i;
	size_t len = 0;

	struct nd_ep *ep = container_of(pep, struct nd_ep, fid);

	if (!ep->qp)
		return -FI_EOPBADSTATE;

	for (i = 0; i < msg->iov_count; i++) {
		if (msg->msg_iov[i].iov_len && !msg->msg_iov[i].iov_base)
			return -FI_EINVAL;
		len += msg->msg_iov[i].iov_len;
	}

	if ((msg->iov_count > min(ep->domain->ainfo.MaxReceiveSge, ND_MSG_IOV_LIMIT) - 1) ||
	    (len > ep->domain->info->ep_attr->max_msg_size))
		return -FI_EINVAL;

	struct nd_cq_entry *entry = (struct nd_cq_entry*)malloc(sizeof(*entry));
	if (!entry)
		return -FI_ENOMEM;
	memset(entry, 0, sizeof(*entry));

	entry->buf = (msg->iov_count == 1) ? msg->msg_iov[0].iov_base : NULL;
	entry->len = len;
	entry->data = msg->data;
	entry->flags = flags | FI_MSG | FI_RECV;
	entry->domain = ep->domain;
	entry->context = msg->context;
	entry->iov_cnt = msg->iov_count;
	entry->seq = InterlockedAdd64(&ep->domain->msg_cnt, 1);

	for (i = 0; i < msg->iov_count; i++)
		entry->iov[i] = msg->msg_iov[i];

	/* store allocated entry in 1st byte of internal data of context */
	if (msg->context)
		ND_FI_CONTEXT(msg->context) = entry;

	ofi_nd_queue_push(&ep->prepost, &entry->queue_item);

	ofi_nd_unexp_match(ep);

	return FI_SUCCESS;
}

static ssize_t ofi_nd_ep_recvv(struct fid_ep *pep, const struct iovec *iov,
			       void **desc,
			       size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_msg msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.addr = src_addr,
		.context = context,
		.data = 0
	};

	assert(pep->fid.fclass == FI_CLASS_EP);

	if (pep->fid.fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	struct nd_ep *ep = container_of(pep, struct nd_ep, fid);

	return ofi_nd_ep_recvmsg(pep, &msg, ep->info->rx_attr->op_flags);
}

static ssize_t ofi_nd_ep_recv(struct fid_ep *pep, void *buf, size_t len,
			      void *desc, fi_addr_t src_addr, void *context)
{
	struct nd_ep *ep = container_of(pep, struct nd_ep, fid);
	ND2_SGE sge = {
		.Buffer = buf,
		.BufferLength = (ULONG)len,
		.MemoryRegionToken = desc
	};
	HRESULT hr = ep->qp->lpVtbl->Receive(ep->qp, context, &sge, 1);
	return H2F(hr);
}

void ofi_nd_send_event(ND2_RESULT *result)
{
	assert(result);
	assert(result->RequestType == Nd2RequestTypeSend);

	struct nd_ep *ep = (struct nd_ep*)result->QueuePairContext;
	assert(ep);
	assert(ep->fid.fid.fclass == FI_CLASS_EP);

	if (ep->cntr_send) {
		if (result->Status != S_OK) {
			InterlockedIncrement64(&ep->cntr_send->err);
		}
		InterlockedIncrement64(&ep->cntr_send->counter);
		WakeByAddressAll((void*)&ep->cntr_send->counter);
	}

	InterlockedIncrement(&ep->cq_send->count);
	WakeByAddressAll((void*)&ep->cq_send->count);
}

#endif /* _WIN32 */

