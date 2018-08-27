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

int ofi_nd_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		   struct fid_eq **peq, void *context);
static int ofi_nd_eq_close(struct fid *fid);
static ssize_t ofi_nd_eq_read(struct fid_eq *peq, uint32_t *pev,
			      void *buf, size_t len, uint64_t flags);
static ssize_t ofi_nd_eq_readerr(struct fid_eq *peq,
				 struct fi_eq_err_entry *buf, uint64_t flags);
static ssize_t ofi_nd_eq_sread(struct fid_eq *peq, uint32_t *pev,
			       void *buf, size_t len, int timeout,
			       uint64_t flags);
static const char *ofi_nd_eq_strerror(struct fid_eq *eq, int prov_errno,
				      const void *err_data, char *buf, size_t len);
static ssize_t ofi_nd_eq_write(struct fid_eq *peq, uint32_t ev,
			       const void *buf, size_t len, uint64_t flags);

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

int ofi_nd_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		   struct fid_eq **peq, void *context)
{
	if (!peq || !fabric || fabric->fid.fclass != FI_CLASS_FABRIC)
		return -FI_EINVAL;

	if (attr)
	{
		if (attr->wait_obj != FI_WAIT_NONE && attr->wait_obj != FI_WAIT_UNSPEC)
			return -FI_EBADFLAGS;
	}

	nd_eq_t *nd_eq_ptr = (nd_eq_t*)calloc(1, sizeof(*nd_eq_ptr));
	if (!nd_eq_ptr)
		return -FI_ENOMEM;

	/*
	nd_eq_ptr->fid.fid.fclass = FI_CLASS_EQ;
	nd_eq_ptr->fid.fid.context = context;
	nd_eq_ptr->fid.fid.ops = &ofi_nd_fi_ops;
	nd_eq_ptr->fid.ops = &ofi_nd_eq_ops;
	*/
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

	*nd_eq_ptr = def;

	InitializeCriticalSection(&nd_eq_ptr->lock);

	nd_eq_ptr->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!nd_eq_ptr->iocp || nd_eq_ptr->iocp == INVALID_HANDLE_VALUE)
	{
		ofi_nd_eq_close(&nd_eq_ptr->fid.fid);
		return H2F(HRESULT_FROM_WIN32(GetLastError()));
	}

	nd_eq_ptr->err = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!nd_eq_ptr->err || nd_eq_ptr->err == INVALID_HANDLE_VALUE)
	{
		ofi_nd_eq_close(&nd_eq_ptr->fid.fid);
		return H2F(HRESULT_FROM_WIN32(GetLastError()));
	}

	*peq = &nd_eq_ptr->fid;

	return FI_SUCCESS;
}

static int ofi_nd_eq_close(struct fid *fid)
{
	nd_eq_t *eq_ptr = container_of(fid, nd_eq_t, fid.fid);

	if (eq_ptr->iocp && eq_ptr->iocp != INVALID_HANDLE_VALUE)
		CloseHandle(eq_ptr->iocp);
	if (eq_ptr->err && eq_ptr->err != INVALID_HANDLE_VALUE)
		CloseHandle(eq_ptr->err);

	DeleteCriticalSection(&eq_ptr->lock);

	free(eq_ptr);
	return FI_SUCCESS;
}

static inline ssize_t ofi_nd_eq_ev2buf(nd_eq_event_t *ev,
				       void *buf, size_t len)
{
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


static ssize_t ofi_nd_eq_read(struct fid_eq *peq, uint32_t *pev,
			      void *buf, size_t len, uint64_t flags)
{
	nd_eq_t *eq = container_of(peq, nd_eq_t, fid);

	DWORD bytes = 0;
	ULONG_PTR key = 0;
	OVERLAPPED *ov = 0;
	ssize_t res = 0;

	nd_eq_event_t *ev = 0;

	if (!eq->count)
		return -FI_EAGAIN;

	/* we have to use critical section here because concurrent thread
	   may read event with FI_PEEK flag */
	EnterCriticalSection(&eq->lock);

	/* check again because it may be changed on critical section barrier */
	if (!eq->count)
	{
		LeaveCriticalSection(&eq->lock);
		return -FI_EAGAIN;
	}

	if (eq->peek)
	{
		ev = eq->peek;
	}
	else
	{
		assert(eq->iocp);
		if (GetQueuedCompletionStatus(eq->iocp, &bytes, &key, &ov, 0))
		{
			ev = container_of(ov, struct nd_eq_event, ov);
		}
	}

	/* in case if no event available, but counter is non-zero - error available */
	if (!ev && eq->count)
	{
		LeaveCriticalSection(&eq->lock);
		return -FI_EAVAIL;
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

	return res;
}

static ssize_t ofi_nd_eq_readerr(struct fid_eq *peq,
				 struct fi_eq_err_entry *buf, uint64_t flags)
{
	nd_eq_t *eq = container_of(peq, nd_eq_t, fid);

	DWORD bytes = 0;
	ULONG_PTR key = 0;
	OVERLAPPED *ov = 0;

	nd_eq_event_t *ev = 0;

	if (!eq->errdata)
	{
		free(eq->errdata);
		eq->errdata = 0;
	}

	if (!GetQueuedCompletionStatus(eq->err, &bytes, &key, &ov, 0))
		return -FI_EAGAIN;

	InterlockedDecrement(&eq->count);
	ev = container_of(ov, nd_eq_event_t, ov);

	if (buf->err_data && buf->err_data_size)
	{
		memcpy(buf, &ev->error, offsetof(struct fi_eq_err_entry, err_data));
		buf->err_data_size = MIN(buf->err_data_size, ev->error.err_data_size);
		memcpy(buf->err_data, ev->error.err_data, buf->err_data_size);
		/* to be sure that the errdata in EQ is NULL */
		eq->errdata = 0;
	}
	else
	{
		/* for compatibility purposes (release < 1.5 or passed err_data_size is 0) */
		memcpy(buf, &ev->error, sizeof(ev->error));
		eq->errdata = ev->error.err_data;
	}

	return FI_SUCCESS;
}

static ssize_t ofi_nd_eq_sread(struct fid_eq *peq, uint32_t *pev,
			       void *buf, size_t len, int timeout,
			       uint64_t flags)
{
	nd_eq_t *nd_eq_ptr = container_of(peq, nd_eq_t, fid);
	ssize_t res = 0;
	int retry = 1;
	LONG zero = 0;
	while(retry)
	{
		do
		{
			if (!WaitOnAddress(
				&nd_eq_ptr->count, &zero, sizeof(nd_eq_ptr->count),
				(DWORD)timeout) && timeout >= 0)
			{
				return -FI_EAGAIN;
			}
		} while (!nd_eq_ptr->count);

		/* we have to use critical section here because concurrent thread
		may read event with FI_PEEK flag */
		EnterCriticalSection(&nd_eq_ptr->lock);

		if (!nd_eq_ptr->count)
		{
			retry = 1;
			LeaveCriticalSection(&nd_eq_ptr->lock);
			if (timeout >= 0)
				return -FI_EAGAIN;
		}
		else
		{
			retry = 0;
		}
	}

	/* if there is peeked item - use it, else - try to read from queue */
	DWORD bytes = 0;
	ULONG_PTR key = 0;
	OVERLAPPED *ov = 0;
	nd_eq_event_t *ev = 0;
	if (nd_eq_ptr->peek)
	{
		ev = nd_eq_ptr->peek;
	}
	else
	{
		assert(nd_eq_ptr->iocp);
		if (GetQueuedCompletionStatus(
			nd_eq_ptr->iocp, &bytes, &key, &ov, 0))
		{
			ev = container_of(ov, struct nd_eq_event, ov);
		}
	}

	/* in case if no event available, but counter is non-zero - error available */
	if (!ev && nd_eq_ptr->count)
	{
		res = -FI_EAVAIL;
		LeaveCriticalSection(&nd_eq_ptr->lock);
		return res;
	}

	res = ofi_nd_eq_ev2buf(ev, buf, len);
	*pev = ev->eq_event;

	if (flags & FI_PEEK)
	{
		nd_eq_ptr->peek = ev;
		/* we updated peek ptr, notify other waiters about this */
		WakeByAddressAll((void*)&nd_eq_ptr->count);
	}
	else
	{
		nd_eq_ptr->peek = NULL;
		InterlockedDecrement(&nd_eq_ptr->count);
		assert(nd_eq_ptr->count >= 0);
	}

	LeaveCriticalSection(&nd_eq_ptr->lock);

	return res;
}

static const char *ofi_nd_eq_strerror(struct fid_eq *eq, int prov_errno,
				      const void *err_data, char *buf, size_t len)
{
	if (buf && len)
		return strncpy(buf, fi_strerror(-prov_errno), len);
	return fi_strerror(-prov_errno);
}

static inline void ofi_nd_eq_free_event(nd_eq_event_t *ev)
{
	if (ev->data)
		free(ev->data);

	if (ev->eq_event == FI_CONNREQ)
	{
		struct fi_eq_cm_entry *cm = (struct fi_eq_cm_entry*)&ev->operation;
		if (cm->info)
			fi_freeinfo(cm->info);
	}

	free(ev);
}

static ssize_t ofi_nd_eq_write(struct fid_eq *peq, uint32_t ev,
			       const void *buf, size_t len, uint64_t flags)
{
	nd_eq_t *eq = container_of(peq, nd_eq_t, fid);

	nd_eq_event_t *custom = (nd_eq_event_t*)calloc(1, sizeof(*custom));
	if (!custom)
		return -FI_ENOMEM;

	custom->is_custom = 1;
	custom->eq_event = ev;
	if (len)
	{
		custom->data = malloc(len);
		if (!custom->data)
		{
			ofi_nd_eq_free_event(custom);
			return -FI_ENOMEM;
		}
		custom->len = len;
		memcpy(custom->data, buf, len);
	}

	ofi_nd_eq_push(eq, custom);

	return len;
}

#endif /* _WIN32 */
