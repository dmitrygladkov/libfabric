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
#include "netdir_log.h"
#include "netdir_misc.h"

#include "ofi_util.h"

static struct fi_ops ofi_nd_fi_ops;
static struct fi_ops_eq ofi_nd_eq_ops;

static int ofi_nd_eq_close(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_EQ);

	nd_eq_t *eq = container_of(fid, nd_eq_t, fid.fid);

	if (eq->iocp && eq->iocp != INVALID_HANDLE_VALUE)
		CloseHandle(eq->iocp);
	if (eq->err && eq->err != INVALID_HANDLE_VALUE)
		CloseHandle(eq->err);

	DeleteCriticalSection(&eq->lock);

	free(eq);
	return FI_SUCCESS;
}

int ofi_nd_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		   struct fid_eq **peq, void *context)
{
	assert(fabric);
	assert(fabric->fid.fclass == FI_CLASS_FABRIC);

	if (attr) {
		if (attr->wait_obj != FI_WAIT_NONE && attr->wait_obj != FI_WAIT_UNSPEC)
			return -FI_EBADFLAGS;
	}

	nd_eq_t *eq = (nd_eq_t*)calloc(1, sizeof(*eq));
	if (!eq)
		return -FI_ENOMEM;

	nd_eq_t def = {
		.fid = {
			.fid = {
				.fclass = FI_CLASS_EQ,
				.context = context,
				.ops = &ofi_nd_fi_ops
			},
			.ops = &ofi_nd_eq_ops
		}
	};

	*eq = def;

	InitializeCriticalSection(&eq->lock);

	eq->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!eq->iocp || eq->iocp == INVALID_HANDLE_VALUE) {
		ofi_nd_eq_close(&eq->fid.fid);
		return H2F(HRESULT_FROM_WIN32(GetLastError()));
	}

	eq->err = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!eq->err || eq->err == INVALID_HANDLE_VALUE) {
		ofi_nd_eq_close(&eq->fid.fid);
		return H2F(HRESULT_FROM_WIN32(GetLastError()));
	}

	*peq = &eq->fid;
	
	return FI_SUCCESS;
}

static ssize_t ofi_nd_eq_read(struct fid_eq *peq, uint32_t *pev,
			      void *buf, size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_eq_readerr(struct fid_eq *peq,
				 struct fi_eq_err_entry *buf, uint64_t flags)
{
	return -FI_ENOSYS;
}

static inline ssize_t ofi_nd_eq_ev2buf(nd_eq_event_t *ev,
				       void *buf, size_t len)
{
	assert(ev);

	size_t copylen = 0;
	char* dst = (char *)buf;

	if (!ev->is_custom)
	{
		switch (ev->eq_event)
		{
		case FI_CONNREQ:
		case FI_CONNECTED:
		case FI_SHUTDOWN:
			copylen = min(sizeof(struct fi_eq_cm_entry), len);
			break;
		case FI_AV_COMPLETE:
		case FI_MR_COMPLETE:
			copylen = min(sizeof(struct fi_eq_entry), len);
			break;
		default:
			ND_LOG_WARN(FI_LOG_EQ, "unknown event type: %d\n",
				   ev->eq_event);
			copylen = min(sizeof(struct fi_eq_entry), len);
			break;
		}
	}

	if (copylen)
		memcpy(dst, &ev->operation, copylen);

	if (ev->len)
	{
		assert(ev->data);
		if (len > copylen)
		{
			dst += copylen;
			memcpy(dst, ev->data, min(len - copylen, ev->len));
			copylen += min(len - copylen, ev->len);
		}
	}
	return (ssize_t)copylen;
}

static ssize_t ofi_nd_eq_sread(struct fid_eq *peq, uint32_t *pev,
			       void *buf, size_t len, int timeout,
			       uint64_t flags)
{
	assert(peq);
	assert(pev);
	assert(peq->fid.fclass == FI_CLASS_EQ);

	nd_eq_t *eq = container_of(peq, nd_eq_t, fid);

	DWORD bytes;
	ULONG_PTR key;
	OVERLAPPED *ov;
	ssize_t res = 0;

	nd_eq_event_t *ev = 0;

	LONG zero = 0;

	while(1)
	{
		do
		{
			if (!WaitOnAddress(
				&eq->count, &zero, sizeof(eq->count),
				(DWORD)timeout) && timeout >= 0)
				return -FI_EAGAIN;
		} while (!eq->count);

		/* we have to use critical section here because concurrent thread
		may read event with FI_PEEK flag */
		EnterCriticalSection(&eq->lock);

		if (!eq->count)
		{
			LeaveCriticalSection(&eq->lock);
			if (timeout >= 0)
				return -FI_EAGAIN;
			else
				continue;
		}

		/* if there is peeked item - use it, else - try to read from queue */
		if (eq->peek)
		{
			ev = eq->peek;
		}
		else
		{
			assert(eq->iocp);
			if (GetQueuedCompletionStatus(
				eq->iocp, &bytes, &key, &ov, 0))
			{
				ev = container_of(ov, nd_eq_event_t, ov);
			}
		}

		/* in case if no event available, but counter is non-zero - error available */
		if (!ev && eq->count)
		{
			res = -FI_EAVAIL;
			goto fn_complete;
		}

		res = ofi_nd_eq_ev2buf(ev, buf, len);
		*pev = ev->eq_event;

		if (flags & FI_PEEK)
		{
			eq->peek = ev;
			/* we updated peek ptr, notify other waiters about this */
			WakeByAddressAll((void*)&eq->count);
		}
		else
		{
			eq->peek = NULL;
			InterlockedDecrement(&eq->count);
			assert(eq->count >= 0);
		}

fn_complete:
		LeaveCriticalSection(&eq->lock);
		return res;
	}
}

static const char *ofi_nd_eq_strerror(struct fid_eq *eq, int prov_errno,
				      const void *err_data, char *buf, size_t len)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_eq_write(struct fid_eq *peq, uint32_t ev,
			       const void *buf, size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_eq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_eq ofi_nd_eq_ops = {
	.size = sizeof(ofi_nd_eq_ops),
	.read = ofi_nd_eq_read,
	.readerr = ofi_nd_eq_readerr,
	.write = ofi_nd_eq_write,
	.sread = ofi_nd_eq_sread,
	.strerror = ofi_nd_eq_strerror
};

#endif /* _WIN32 */

