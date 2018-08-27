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

static int ofi_nd_domain_close(fid_t fid);
int ofi_nd_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		       struct fid_domain **pdomain, void *context);
static int ofi_nd_domain_bind(struct fid *fid, struct fid *bfid,
			      uint64_t flags);

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


static int ofi_nd_domain_close(fid_t fid)
{
	nd_domain_t *domain = container_of(fid, nd_domain_t, fid.fid);

	DWORD ref = 0;

	if (domain->cq)
	{
		domain->cq->lpVtbl->CancelOverlappedRequests(domain->cq);
		domain->cq->lpVtbl->Release(domain->cq);
	}

	if (domain->info)
		fi_freeinfo(domain->info);

	if (domain->adapter_file && domain->adapter_file != INVALID_HANDLE_VALUE)
		CloseHandle(domain->adapter_file);

	if (domain->adapter)
	{
		ref = domain->adapter->lpVtbl->Release(domain->adapter);
	}

	free(domain);

	return FI_SUCCESS;
}

static void ofi_nd_domain_event(nd_event_base_t *base, DWORD bytes)
{
}

static void ofi_nd_domain_err(nd_event_base_t *base, DWORD bytes, DWORD err)
{
}

void CALLBACK domain_io_cb(DWORD err, DWORD bytes, LPOVERLAPPED ov)
{
	nd_event_base_t *base_ptr = container_of(ov, nd_event_base_t, ov);

	ND_LOG_DEBUG(FI_LOG_EP_CTRL,
		"IO callback: err: %s, bytes: %d\n",
		ofi_nd_error_str(err), bytes);

	if (err)
	{
		base_ptr->error_cb(base_ptr, bytes, err);
	}
	else
	{
		base_ptr->event_cb(base_ptr, bytes);
	}
}

static HRESULT ofi_nd_domain_notify(nd_domain_t *domain)
{
	assert(domain);
	assert(domain->fid.fid.fclass == FI_CLASS_DOMAIN);
	assert(domain->cq);

	nd_event_base_t base = {
		.event_cb = ofi_nd_domain_event,
		.error_cb = ofi_nd_domain_err
	};

	domain->base = base;
	return domain->cq->lpVtbl->Notify(domain->cq, ND_CQ_NOTIFY_ANY, &domain->base.ov);
}

int ofi_nd_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		       struct fid_domain **pdomain, void *context)
{
	if (!pdomain)
		return -FI_EINVAL;

	nd_domain_t *nd_domain_ptr = (nd_domain_t*)calloc(1, sizeof(*nd_domain_ptr));
	if (!nd_domain_ptr)
		return -FI_ENOMEM;

	nd_domain_ptr->fid.fid = ofi_nd_fid;
	nd_domain_ptr->fid.ops = &ofi_nd_domain_ops;
	nd_domain_ptr->fid.mr = &ofi_nd_mr_ops;
	nd_domain_ptr->info = fi_dupinfo(info);

	dlist_init(&nd_domain_ptr->ep_list);

	struct sockaddr *addr = NULL;
	int res = ofi_nd_lookup_adapter(info->domain_attr->name,
				&nd_domain_ptr->adapter, &addr);
	if (res || !nd_domain_ptr->adapter)
	{
		ofi_nd_domain_close(&nd_domain_ptr->fid.fid);
		return res;
	}
	memcpy(&nd_domain_ptr->addr, addr, ofi_sizeofaddr(addr));

	HRESULT hr = nd_domain_ptr->adapter->lpVtbl->CreateOverlappedFile(nd_domain_ptr->adapter,
							   &nd_domain_ptr->adapter_file);
	if (FAILED(hr))
	{
		ofi_nd_domain_close(&nd_domain_ptr->fid.fid);
		return H2F(hr);
	}

	if (!BindIoCompletionCallback(nd_domain_ptr->adapter_file, domain_io_cb, 0))
	{
		ofi_nd_domain_close(&nd_domain_ptr->fid.fid);
		return HRESULT_FROM_WIN32(GetLastError());
	}

	nd_domain_ptr->ainfo.InfoVersion = ND_VERSION_2;
	ULONG len = sizeof(nd_domain_ptr->ainfo);
	hr = nd_domain_ptr->adapter->lpVtbl->Query(nd_domain_ptr->adapter,
				&nd_domain_ptr->ainfo, &len);

	if (FAILED(hr))
	{
		ofi_nd_domain_close(&nd_domain_ptr->fid.fid);
		return H2F(hr);
	}

	hr = nd_domain_ptr->adapter->lpVtbl->CreateCompletionQueue(
		nd_domain_ptr->adapter, &IID_IND2CompletionQueue, nd_domain_ptr->adapter_file,
		nd_domain_ptr->ainfo.MaxCompletionQueueDepth, 0, 0,
		(void**)&nd_domain_ptr->cq);

	if (FAILED(hr))
	{
		ofi_nd_domain_close(&nd_domain_ptr->fid.fid);
		return H2F(hr);
	}

	*pdomain = &nd_domain_ptr->fid;

	ND_LOG_DEBUG(FI_LOG_DOMAIN, "domain notification OV: %p\n", &nd_domain_ptr->base.ov);
	hr = ofi_nd_domain_notify(nd_domain_ptr);
	if (FAILED(hr))
	{
		ofi_nd_domain_close(&nd_domain_ptr->fid.fid);
		return H2F(hr);
	}

	return FI_SUCCESS;
}

static int ofi_nd_domain_bind(struct fid *fid, struct fid *bfid,
			      uint64_t flags)
{
	nd_domain_t *domain = container_of(fid, nd_domain_t, fid.fid);

	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		domain->eq = container_of(bfid, nd_eq_t, fid.fid);
		domain->eq_flags = flags;
		break;
	default:
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

#endif /* _WIN32 */

