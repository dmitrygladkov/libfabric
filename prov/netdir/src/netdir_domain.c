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

#include "ofi.h"
#include "ofi_util.h"
#include "ofi_enosys.h"
#include "rdma/fabric.h"
#include "rdma/fi_domain.h"

static struct fi_ops_domain ofi_nd_domain_ops;
static struct fi_ops_mr ofi_nd_mr_ops;
static struct fid ofi_nd_fid;

static int ofi_nd_domain_close(fid_t fid)
{
	assert(fid->fclass == FI_CLASS_DOMAIN);

	nd_domain_t *domain = container_of(fid, nd_domain_t, fid.fid);

	DWORD ref = 0;

	if (domain->cq)
	{
		domain->cq->lpVtbl->CancelOverlappedRequests(domain->cq);
		while (!domain->cq_canceled)
			SwitchToThread();

		domain->cq->lpVtbl->Release(domain->cq);
	}
	if (domain->info)
		fi_freeinfo(domain->info);

	if (domain->adapter_file && domain->adapter_file != INVALID_HANDLE_VALUE)
		CloseHandle(domain->adapter_file);

	if (domain->adapter)
	{
		ref = domain->adapter->lpVtbl->Release(domain->adapter);
		ND_LOG_DEBUG(FI_LOG_EP_CTRL, "domain->adapter ref count: %d\n", ref);
	}

	free(domain);
	return FI_SUCCESS;
}


static HRESULT ofi_nd_domain_notify(nd_domain_t *domain);

static void ofi_nd_domain_event(nd_event_base_t* base, DWORD bytes)
{
	OFI_UNUSED(bytes);

	assert(base);
	nd_domain_t *domain = container_of(base, nd_domain_t, ov);

	assert(domain->fid.fid.fclass == FI_CLASS_DOMAIN);
	assert(domain->cq);

#define RESULT_MAX_SIZE 256
	ND2_RESULT result[RESULT_MAX_SIZE];
	DWORD count;
	do
	{
		count = domain->cq->lpVtbl->GetResults(domain->cq, result, RESULT_MAX_SIZE);
		for (size_t i = 0; i < count; i++)
		{
			ND_LOG_DEBUG(FI_LOG_EP_DATA, "Domain event is %d with status %s\n",
				     result[i].RequestType,
				     ofi_nd_error_str(result[i].Status));
			switch (result[i].RequestType)
			{
			case Nd2RequestTypeReceive:
				ofi_nd_receive_event(&result[i]);
				break;
			case Nd2RequestTypeSend:
				ofi_nd_send_event(&result[i]);
				break;
			case Nd2RequestTypeRead:
				//ofi_nd_read_event(&result[i]);
				break;
			case Nd2RequestTypeWrite:
				//ofi_nd_write_event(&result[i]);
				break;
			default:
				/* shouldn't go here */
				NODEFAULT;
			}

			/* Let's walk through sending queue to send data 
			 * that are ready to be transmitted */
			nd_ep_t *ep = (nd_ep_t*)result[i].QueuePairContext;
			ofi_nd_ep_progress(ep);
		}
	} while (count == _countof(result));


	ofi_nd_domain_notify(domain);
}

static void ofi_nd_domain_err(nd_event_base_t* base, DWORD bytes, DWORD err)
{
	assert(0);
}

static HRESULT ofi_nd_domain_notify(nd_domain_t *domain)
{
	assert(domain);
	assert(domain->fid.fid.fclass == FI_CLASS_DOMAIN);
	assert(domain->cq);

	nd_event_base_t ov = {
		.event_cb = ofi_nd_domain_event,
		.err_cb = ofi_nd_domain_err
	};

	domain->ov = ov;
	return domain->cq->lpVtbl->Notify(domain->cq, ND_CQ_NOTIFY_ANY, &domain->ov.ov);
}

int ofi_nd_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		       struct fid_domain **pdomain, void *context)
{
	OFI_UNUSED(context);

	assert(fabric);
	assert(fabric->fid.fclass == FI_CLASS_FABRIC);
	assert(info);
	assert(info->domain_attr);
	assert(info->domain_attr->name);

	if (!info || !info->domain_attr || !info->domain_attr->name)
		return -FI_EINVAL;

	HRESULT hr;
	int res;
	struct sockaddr* addr;

	nd_domain_t *domain = (nd_domain_t*)calloc(1, sizeof(*domain));
	if (!domain)
		return -FI_ENOMEM;

	nd_domain_t def = {
		.fid = {
			.fid = ofi_nd_fid,
			.ops = &ofi_nd_domain_ops,
			.mr = &ofi_nd_mr_ops
		},
		.info = fi_dupinfo(info)
	};

	*domain = def;

	dlist_init(&domain->ep_list);

	res = ofi_nd_lookup_adapter(info->domain_attr->name, &domain->adapter, &addr);
	if (res || !domain->adapter)
	{
		ofi_nd_domain_close(&domain->fid.fid);
		return res;
	}

	memcpy(&domain->addr, addr, ofi_sizeofaddr(addr));

	hr = domain->adapter->lpVtbl->CreateOverlappedFile(domain->adapter,
							   &domain->adapter_file);

	if (FAILED(hr))
		goto hr_failed;

	if (!BindIoCompletionCallback(domain->adapter_file, domain_io_cb, 0))
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto hr_failed;
	}

	domain->ainfo.InfoVersion = ND_VERSION_2;
	ULONG len = sizeof(domain->ainfo);
	hr = domain->adapter->lpVtbl->Query(domain->adapter, &domain->ainfo,
					    &len);
	if (FAILED(hr))
		goto hr_failed;

	hr = domain->adapter->lpVtbl->CreateCompletionQueue(
		domain->adapter, &IID_IND2CompletionQueue, domain->adapter_file,
		domain->ainfo.MaxCompletionQueueDepth, 0, 0,
		(void**)&domain->cq);
	if (FAILED(hr))
		goto hr_failed;

	*pdomain = &domain->fid;

	ND_LOG_DEBUG(FI_LOG_DOMAIN, "domain notification OV: %p\n", &domain->ov.ov);
	hr = ofi_nd_domain_notify(domain);
	if (FAILED(hr))
		goto hr_failed;

	return FI_SUCCESS;

hr_failed:
	ofi_nd_domain_close(&domain->fid.fid);
	return H2F(hr);
}

static int ofi_nd_domain_bind(struct fid *fid, struct fid *bfid,
			      uint64_t flags)
{
	return -FI_ENOSYS;
}

typedef struct ofi_nd_mr_ov {
	nd_event_base_t	base;
	nd_eq_t	*eq;
	fid_t		fid;
	void		*context;
	LONG		cnt;
} ofi_nd_mr_ov_t;

static void ofi_nd_mr_ov_free(nd_event_base_t* base)
{
	ofi_nd_mr_ov_t *ov = container_of(base, ofi_nd_mr_ov_t, base);
	if (ov->base.ov.hEvent && ov->base.ov.hEvent != INVALID_HANDLE_VALUE)
		CloseHandle(ov->base.ov.hEvent);

	free(ov);
}

static void ofi_nd_mr_ov_event(nd_event_base_t* base, DWORD bytes)
{
	OFI_UNUSED(bytes);

	HRESULT hr;

	ofi_nd_mr_ov_t *ov = container_of(base, ofi_nd_mr_ov_t, base);

	/* this is sync mr reg operation */
	if (ov->cnt)
	{
		if (!InterlockedDecrement(&ov->cnt))
		{
			ofi_nd_mr_ov_free(&ov->base);
		}
		return;
	}

	assert(ov->eq);
	assert(ov->fid);
	assert(ov->fid->fclass == FI_CLASS_MR);

	nd_mr_t *mr = container_of(ov->fid, nd_mr_t, fid.fid);
	assert(mr->mr);
	mr->fid.key = mr->mr->lpVtbl->GetRemoteToken(mr->mr);
	mr->fid.mem_desc = (void *)(uintptr_t)mr->mr->lpVtbl->GetLocalToken(mr->mr);

	struct fi_eq_entry entry = {.fid = ov->fid, .context = ov->context};
	ofi_nd_mr_ov_free(base);

	nd_eq_event_t *err;
	nd_eq_event_t *ev = (nd_eq_event_t*)malloc(sizeof(*ev));
	if (!ev)
	{
		hr = ND_NO_MEMORY;
		goto fn_fail;
	}
	memset(ev, 0, sizeof(*ev));
	ev->eq_event = FI_MR_COMPLETE;
	ev->operation = entry;
	ofi_nd_eq_push(ov->eq, ev);
	return;

fn_fail:
	err = (nd_eq_event_t*)calloc(1, sizeof(*err));
	if (!err)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL,
			   "failed to allocate error event\n");
		return;
	}

	err->error.err = -H2F(hr);
	err->error.prov_errno = (int)hr;
	err->error.fid = ov->fid;
	ofi_nd_eq_push_err(ov->eq, err);
}

static void ofi_nd_mr_ov_err(nd_event_base_t* base, DWORD bytes, DWORD err)
{
	assert(0);
}

static int ofi_nd_mr_close(struct fid *fid)
{
	ND_LOG_DEBUG(FI_LOG_MR, "closing mr\n");
	assert(fid->fclass == FI_CLASS_MR);
	if (fid->fclass != FI_CLASS_MR)
		return -FI_EINVAL;

	nd_mr_t *mr = container_of(fid, nd_mr_t, fid.fid);

	if (mr->mr)
		mr->mr->lpVtbl->Release(mr->mr);

	if (mr->wnd)
		mr->wnd->lpVtbl->Release(mr->wnd);

	free(mr);

	return FI_SUCCESS;
}

int ofi_nd_mr_reg(struct fid *fid, const void *buf, size_t len,
		  uint64_t access, uint64_t offset, uint64_t requested_key,
		  uint64_t flags, struct fid_mr **pmr, void *context)
{
	OFI_UNUSED(requested_key);

	assert(fid->fclass == FI_CLASS_DOMAIN);
	assert(!offset);

	HRESULT hr;

	if (fid->fclass != FI_CLASS_DOMAIN)
		return -FI_EINVAL;
	if (offset)
		return -FI_EINVAL;
	if (flags)
		return -FI_EINVAL;

	nd_domain_t *domain = container_of(fid, nd_domain_t, fid.fid);

	assert(domain->adapter);
	assert(domain->adapter_file);

	nd_mr_t *mr = (nd_mr_t*)calloc(1, sizeof(*mr));
	if (!mr)
		return -FI_ENOMEM;

	nd_mr_t def = {
		.fid = {
			.fid = ofi_nd_fid
		}
	};

	*mr = def;

	hr = domain->adapter->lpVtbl->CreateMemoryRegion(
		domain->adapter, &IID_IND2MemoryRegion, domain->adapter_file,
		(void**)&mr->mr);

	if (FAILED(hr))
		goto fn_fail;

	ULONG ind2flag = 0;

	if (access & FI_REMOTE_READ)
		ind2flag |= ND_MR_FLAG_ALLOW_REMOTE_READ;
	if (access & FI_REMOTE_WRITE)
		ind2flag |= ND_MR_FLAG_ALLOW_REMOTE_WRITE;
	if ((access & FI_WRITE) || (access & FI_RECV))
		ind2flag |= ND_MR_FLAG_ALLOW_LOCAL_WRITE;

	/* there is bug in mlx4 module: it always generates
	   IO completion (even for cases when hEvent value
	   of OVERLAPPED structure is initialized). To
	   workaround this we have to use dynamically allocated
	   ov */
	ofi_nd_mr_ov_t *ov = (ofi_nd_mr_ov_t*)calloc(1, sizeof(*ov));
	if (!ov)
	{
		hr = ND_NO_MEMORY;
		goto fn_fail;
	}
	memset(ov, 0, sizeof(*ov));

	ofi_nd_mr_ov_t ovdef = {
		.base = {
			.free = ofi_nd_mr_ov_free,
			.event_cb = ofi_nd_mr_ov_event,
			.err_cb = ofi_nd_mr_ov_err
		},
		.eq = domain->eq,
		.fid = &mr->fid.fid,
		.context = context
	};

	*ov = ovdef;
	if (!(domain->eq_flags & FI_MR_COMPLETE))
	{
		ov->cnt = 2;
		ov->base.ov.hEvent = CreateEvent(0, TRUE, FALSE, NULL);
	}

	hr = mr->mr->lpVtbl->Register(mr->mr, buf, len, ind2flag, &ov->base.ov);
	if (FAILED(hr))
	{
		ofi_nd_mr_ov_free(&ov->base);
		goto fn_fail;
	}

	if (!(domain->eq_flags & FI_MR_COMPLETE))
	{
		/* sync memory registration */
		hr = mr->mr->lpVtbl->GetOverlappedResult(mr->mr, &ov->base.ov, TRUE);
		if (!InterlockedDecrement(&ov->cnt))
			ofi_nd_mr_ov_free(&ov->base);

		if (FAILED(hr))
			goto fn_fail;

		mr->fid.key = mr->mr->lpVtbl->GetRemoteToken(mr->mr);
		mr->fid.mem_desc = (void *)(uintptr_t)mr->mr->lpVtbl->GetLocalToken(mr->mr);
	}
	else
	{
		/* async memory registration */
		hr = mr->mr->lpVtbl->Register(
			mr->mr, buf, len, ind2flag, &ov->base.ov);
		if (FAILED(hr))
		{
			ofi_nd_mr_ov_free(&ov->base);
			goto fn_fail;
		}
	}

	*pmr = &mr->fid;

	return FI_SUCCESS;

fn_fail:
	ofi_nd_mr_close(&mr->fid.fid);
	return H2F(hr);
}

int ofi_nd_mr_regv(struct fid *fid, const struct iovec *iov,
		   size_t count, uint64_t access,
		   uint64_t offset, uint64_t requested_key,
		   uint64_t flags, struct fid_mr **mr, void *context)
{
	OFI_UNUSED(fid);
	OFI_UNUSED(iov);
	OFI_UNUSED(count);
	OFI_UNUSED(access);
	OFI_UNUSED(offset);
	OFI_UNUSED(requested_key);
	OFI_UNUSED(flags);
	OFI_UNUSED(fid);
	OFI_UNUSED(mr);
	OFI_UNUSED(context);

	/* This functionality wasn't implemented due to impossibility
	 * to do it by means of ND services. To avoid problems in future,
	 * just to not implement it until no support from ND */

	assert(0);
	return FI_SUCCESS;
}

int ofi_nd_mr_regattr(struct fid *fid, const struct fi_mr_attr *attr,
		      uint64_t flags, struct fid_mr **mr)
{
	OFI_UNUSED(fid);
	OFI_UNUSED(attr);
	OFI_UNUSED(flags);
	OFI_UNUSED(mr);

	assert(0);
	return FI_SUCCESS;
}

static struct fi_ops_domain ofi_nd_domain_ops = {
	.size = sizeof(ofi_nd_domain_ops),
	.av_open = fi_no_av_open,
	.cq_open = ofi_nd_cq_open,
	.endpoint = ofi_nd_endpoint,
	.scalable_ep = fi_no_scalable_ep,
	.cntr_open = ofi_nd_cntr_open,
	.poll_open = fi_no_poll_open,
};

static struct fi_ops_mr ofi_nd_mr_ops = {
	.size = sizeof(ofi_nd_mr_ops),
	.reg = ofi_nd_mr_reg,
	.regv = ofi_nd_mr_regv,
	.regattr = ofi_nd_mr_regattr
};

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_domain_close,
	.bind = ofi_nd_domain_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};

static struct fid ofi_nd_fid = {
	.fclass = FI_CLASS_DOMAIN,
	.context = NULL,
	.ops = &ofi_nd_fi_ops
};

#endif /* _WIN32 */

