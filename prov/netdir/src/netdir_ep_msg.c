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
#include "netdir_log.h"
#include "netdir_misc.h"

#include "rdma/fabric.h"
#include "rdma/fi_endpoint.h"

#include "ofi.h"
#include "ofi_util.h"

static ssize_t
ofi_nd_ep_sendmsg(struct fid_ep *pep, const struct fi_msg *msg, uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t
ofi_nd_ep_inject(struct fid_ep *pep, const void *buf, size_t len,
	fi_addr_t dest_addr)
{
	return -FI_ENOSYS;
}

ssize_t
ofi_nd_ep_injectdata(struct fid_ep *pep, const void *buf, size_t len,
		     uint64_t data, fi_addr_t dest_addr)
{
	return -FI_ENOSYS;
}

static ssize_t
ofi_nd_ep_senddata(struct fid_ep *pep, const void *buf, size_t len, void *desc,
				  uint64_t data, fi_addr_t dest_addr, void *context)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_ep_send(struct fid_ep *pep, const void *buf, size_t len,
			      void *desc, fi_addr_t dest_addr, void *context)
{
	return ofi_nd_ep_senddata(pep, buf, len, desc, 0, dest_addr, context);
}

static ssize_t
ofi_nd_ep_sendv(struct fid_ep *pep, const struct iovec *iov,
			       void **desc, size_t count, fi_addr_t dest_addr,
			       void *context)
{
	return -FI_ENOSYS;
}

#define ND_FI_CONTEXT(ptr) ((struct fi_context*)(ptr))->internal[0]

static ssize_t
ofi_nd_ep_recvmsg(struct fid_ep *pep, const struct fi_msg *msg,
				 uint64_t flags)
{
	if (pep->fid.fclass != FI_CLASS_EP || !msg)
		return -FI_EINVAL;

	size_t i = 0;
	size_t len = 0;

	nd_ep_t *ep_ptr = container_of(pep, nd_ep_t, fid);

	if (!ep_ptr->qp)
		return -FI_EOPBADSTATE;

	for (i = 0; i < msg->iov_count; i++)
	{
		if (msg->msg_iov[i].iov_len && !msg->msg_iov[i].iov_base)
			return -FI_EINVAL;

		len += msg->msg_iov[i].iov_len;
	}

	/*
	if ((msg->iov_count > min(ep_ptr->domain->ainfo.MaxReceiveSge, ND_MSG_IOV_LIMIT) - 1) ||
	    (len > ep_ptr->domain->info->ep_attr->max_msg_size))
		return -FI_EINVAL;
	*/
	nd_cq_entry_t *entry_ptr = (nd_cq_entry_t *)calloc(1, sizeof(*entry_ptr));
	if (!entry_ptr)
		return -FI_ENOMEM;
	memset(entry_ptr, 0, sizeof(*entry_ptr));

	entry_ptr->buf = (msg->iov_count == 1) ? msg->msg_iov[0].iov_base : NULL;
	entry_ptr->len = len;
	entry_ptr->data = msg->data;
	entry_ptr->flags = flags | FI_MSG | FI_RECV;
	entry_ptr->domain = entry_ptr->domain;
	entry_ptr->context = msg->context;
	entry_ptr->iov_cnt = msg->iov_count;
	/* entry_ptr->seq = InterlockedAdd64(&ep_ptr->domain->msg_cnt, 1); */

	for (i = 0; i < msg->iov_count; i++)
		entry_ptr->iov[i] = msg->msg_iov[i];

	/* store allocated entry in 1st byte of internal data of context */
	if (msg->context)
		ND_FI_CONTEXT(msg->context) = entry_ptr;

	ofi_nd_queue_push(&ep_ptr->prepost, &entry_ptr->queue_item);

	return FI_SUCCESS;
}

static ssize_t
ofi_nd_ep_recvv(struct fid_ep *pep, const struct iovec *iov,
			       void **desc, size_t count, fi_addr_t src_addr,
			       void *context)
{
	struct fi_msg msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.addr = src_addr,
		.context = context,
		.data = 0
	};

	if (pep->fid.fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	nd_ep_t *ep_ptr = container_of(pep, nd_ep_t, fid);

	return ofi_nd_ep_recvmsg(pep, &msg, ep_ptr->info->rx_attr->op_flags);
}

static ssize_t
ofi_nd_ep_recv(struct fid_ep *pep, void *buf, size_t len,
			      void *desc, fi_addr_t src_addr, void *context)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len
	};

	return ofi_nd_ep_recvv(pep, &iov, &desc, 1, src_addr, context);
}

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

#endif /* _WIN32 */

