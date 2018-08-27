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

#include "rdma/fabric.h"
#include "ofi_util.h"

static int ofi_nd_cq_close(struct fid *fid);
int ofi_nd_cq_open(struct fid_domain *pdomain, struct fi_cq_attr *attr,
		   struct fid_cq **pcq_fid, void *context);
static ssize_t ofi_nd_cq_read(struct fid_cq *pcq, void *buf, size_t count);
static ssize_t ofi_nd_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
				  fi_addr_t *src_addr);
static ssize_t ofi_nd_cq_readerr(struct fid_cq *pcq, struct fi_cq_err_entry *buf,
				 uint64_t flags);
static ssize_t ofi_nd_cq_sread(struct fid_cq *pcq, void *buf, size_t count,
			       const void *cond, int timeout);
static ssize_t ofi_nd_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
				   fi_addr_t *src_addr, const void *cond, int timeout);
static const char *ofi_nd_cq_strerror(struct fid_cq *cq, int prov_errno,
				      const void *err_data, char *buf, size_t len);

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

static int ofi_nd_cq_close(struct fid *fid)
{
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
	if (pdomain->fid.fclass != FI_CLASS_DOMAIN)
		return -FI_EINVAL;

	if (attr)
	{
		if (attr->wait_obj != FI_WAIT_NONE &&
		    attr->wait_obj != FI_WAIT_UNSPEC)
			return -FI_EBADFLAGS;
	}

	nd_cq_t *nd_cq_ptr = (nd_cq_t*)calloc(1, sizeof(*nd_cq_ptr));
	if (!nd_cq_ptr)
		return -FI_ENOMEM;

	nd_cq_t def = {
		.fid = {
			.fid = ofi_nd_fid,
			.ops = &ofi_nd_cq_ops
		},
		.format = attr ? attr->format : FI_CQ_FORMAT_CONTEXT
	};

	*nd_cq_ptr = def;

	nd_domain_t *domain = container_of(pdomain, struct nd_domain, fid);
	assert(domain->adapter);
	assert(domain->adapter_file);

	HRESULT hr = ERROR_SUCCESS;
	nd_cq_ptr->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!nd_cq_ptr->iocp || nd_cq_ptr->iocp == INVALID_HANDLE_VALUE) {
		hr = -FI_EINVAL;
		ofi_nd_cq_close(&nd_cq_ptr->fid.fid);
		return H2F(hr);
	}
	nd_cq_ptr->err = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!nd_cq_ptr->err || nd_cq_ptr->err == INVALID_HANDLE_VALUE) {
		hr = -FI_EINVAL;
		ofi_nd_cq_close(&nd_cq_ptr->fid.fid);
		return H2F(hr);
	}

	*pcq_fid = &nd_cq_ptr->fid;

	return FI_SUCCESS;
}

static inline void ofi_nd_free_cq_entry(struct nd_cq_entry *entry)
{
	assert(entry);

	if (entry->prefix)
	{
		free(entry->prefix);
	}

	if (entry->inline_buf)
	{
		free(entry->inline_buf);
	}

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

static uint64_t ofi_nd_cq_sanitize_flags(uint64_t flags)
{
	return (flags & (FI_SEND | FI_RECV | FI_RMA | FI_ATOMIC |
		FI_MSG | FI_TAGGED |
		FI_READ | FI_WRITE |
		FI_REMOTE_READ | FI_REMOTE_WRITE |
		FI_REMOTE_CQ_DATA | FI_MULTI_RECV));
}

static void ofi_nd_cq_ov2buf(struct nd_cq *cq, OVERLAPPED_ENTRY *ov,
			     void* buf, ULONG count)
{
	ULONG i;
	struct nd_msgprefix *prefix;

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
		break;
	}
}

static ssize_t ofi_nd_cq_read(struct fid_cq *pcq, void *buf, size_t count)
{
	if (pcq->fid.fclass != FI_CLASS_CQ)
		return -FI_EINVAL;

	nd_cq_t *cq = container_of(pcq, nd_cq_t, fid);
	if (!cq->count)
		return -FI_EAGAIN;

	ULONG cnt = (ULONG)count;
	ULONG dequeue = 0;
	ssize_t res = 0;
	OVERLAPPED_ENTRY _ov[256];

	OVERLAPPED_ENTRY *ov = (cnt <= _countof(_ov)) ?
		_ov : malloc(cnt * sizeof(*ov));

	if (!ov)
	{
		return -FI_ENOMEM;
	}

	if (!GetQueuedCompletionStatusEx(cq->iocp, ov, cnt, &dequeue, 0, FALSE) ||
	    !dequeue)
	{
		res = cq->count ? -FI_EAVAIL : -FI_EAGAIN;
		if (ov != _ov)
			free(ov);
		return res;
	}

	ofi_nd_cq_ov2buf(cq, ov, buf, dequeue);
	res = (ssize_t)dequeue;
	InterlockedAdd(&cq->count, -(LONG)dequeue);

	if (ov != _ov)
		free(ov);
	return res;
}

static ssize_t ofi_nd_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
				  fi_addr_t *src_addr)
{
	size_t i;
	for(i = 0; i < count; i++)
		src_addr[i] = FI_ADDR_NOTAVAIL;
	return ofi_nd_cq_read(cq, buf, count);
}

static ssize_t ofi_nd_cq_readerr(struct fid_cq *pcq, struct fi_cq_err_entry *buf,
				 uint64_t flags)
{
	if (pcq->fid.fclass != FI_CLASS_CQ)
		return -FI_EINVAL;

	nd_cq_t *cq = container_of(pcq, nd_cq_t, fid);

	ULONG_PTR key = 0;
	DWORD bytes = 0;
	OVERLAPPED *ov = 0;

	if (!cq->count)
		return -FI_EAGAIN;

	assert(cq->err && cq->err != INVALID_HANDLE_VALUE);
	if (!GetQueuedCompletionStatus(cq->err, &bytes, &key, &ov, 0))
		return -FI_EAGAIN;

	nd_cq_entry_t *entry = container_of(ov, nd_cq_entry_t, base.ov);

	buf->op_context = entry->result.RequestContext;
	buf->flags = entry->flags;
	buf->len = entry->len;
	buf->buf = entry->buf;
	buf->data = entry->data;
	buf->tag = 0; /* while tagged send/recv isn't added */
	buf->olen = 0;
	buf->err = -H2F(entry->result.Status);
	buf->prov_errno = entry->result.Status;
	buf->err_data_size = 0;

	InterlockedDecrement(&cq->count);
	assert(cq->count >= 0);

	return FI_SUCCESS;
}

static ssize_t ofi_nd_cq_sread(struct fid_cq *pcq, void *buf, size_t count,
			       const void *cond, int timeout)
{
	if (pcq->fid.fclass != FI_CLASS_CQ)
		return -FI_EINVAL;

	nd_cq_t *cq = container_of(pcq, nd_cq_t, fid);

	ULONG cnt = (ULONG)count;
	ULONG dequeue = 0;
	ssize_t res = 0;
	OVERLAPPED_ENTRY _ov[256];

	OVERLAPPED_ENTRY *ov = (cnt <= _countof(_ov)) ?
		_ov : malloc(cnt * sizeof(*ov));

	if (!ov)
	{
		return -FI_ENOMEM;
	}

	LONG zero = 0;
	OFI_ND_TIMEOUT_INIT(timeout);
	do
	{
		do
		{
			if (!WaitOnAddress(
				&cq->count, &zero, sizeof(cq->count),
				(DWORD)timeout) && timeout >= 0)
			{
				res = -FI_EAGAIN;
				if (ov != _ov)
					free(ov);
				return res;
			}
		} while (!cq->count && !OFI_ND_TIMEDOUT());

		if (!cq->count)
		{
			res = -FI_EAGAIN;
			if (ov != _ov)
				free(ov);
			return res;
		}


		assert(cq->iocp && cq->iocp != INVALID_HANDLE_VALUE);
		if (!GetQueuedCompletionStatusEx(cq->iocp, ov, cnt, &dequeue, 0, FALSE) ||
		    !dequeue)
		{
			if (cq->count)
			{
				res = -FI_EAVAIL;
				if (ov != _ov)
					free(ov);
				return res;
			}
			else
			{
				continue;
			}
		}

		ofi_nd_cq_ov2buf(cq, ov, buf, dequeue);
		res = (ssize_t)dequeue;
		InterlockedAdd(&cq->count, -(LONG)dequeue);
		assert(cq->count >= 0);
		if (ov != _ov)
			free(ov);
		return res;
	} while (!OFI_ND_TIMEDOUT());

	if (ov != _ov)
		free(ov);
	return res;
}

static ssize_t ofi_nd_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
				   fi_addr_t *src_addr, const void *cond,
				   int timeout)
{
	size_t i;
	for (i = 0; i < count; i++)
		src_addr[i] = FI_ADDR_NOTAVAIL;
	return ofi_nd_cq_sread(cq, buf, count, cond, timeout);
}

static const char *ofi_nd_cq_strerror(struct fid_cq *cq, int prov_errno,
				      const void *err_data, char *buf,
				      size_t len)
{
	if (buf && len)
		return strncpy(buf, fi_strerror(-prov_errno), len);
	return fi_strerror(-prov_errno);
}

#endif /* _WIN32 */

