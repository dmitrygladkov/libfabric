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

int ofi_nd_endpoint(struct fid_domain *pdomain, struct fi_info *info,
	struct fid_ep **ep_fid, void *context);
static int ofi_nd_ep_control(struct fid *fid, int command, void *arg);
static int ofi_nd_ep_close(struct fid *fid);
static int ofi_nd_ep_connect(struct fid_ep *pep, const void *addr,
			     const void *param, size_t paramlen);
static int ofi_nd_ep_accept(struct fid_ep *pep, const void *param,
		size_t paramlen);
static int ofi_nd_ep_getname(fid_t fid, void *addr, size_t *addrlen);
static int ofi_nd_ep_bind(fid_t pep, fid_t bfid, uint64_t flags);
static int ofi_nd_ep_shutdown(struct fid_ep *pep, uint64_t flags);
static ssize_t ofi_nd_ep_cancel(fid_t fid, void *context);

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_ep_close,
	.bind = ofi_nd_ep_bind,
	.control = ofi_nd_ep_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_cm ofi_nd_cm_ops = {
	.size = sizeof(ofi_nd_cm_ops),
	.setname = fi_no_setname,
	.getname = ofi_nd_ep_getname,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = ofi_nd_ep_shutdown,
	.join = fi_no_join,
};

extern struct fi_ops_msg ofi_nd_ep_msg;
extern struct fi_ops_rma ofi_nd_ep_rma;

static struct fi_ops_ep ofi_nd_ep_ops = {
	.size = sizeof(ofi_nd_ep_ops),
	.cancel = ofi_nd_ep_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

int ofi_nd_endpoint(struct fid_domain *pdomain, struct fi_info *info,
	struct fid_ep **ep_fid, void *context)
{
	if (!ep_fid)
		return -FI_EINVAL;

	nd_domain_t *domain = container_of(pdomain, nd_domain_t, fid);
	nd_ep_t *nd_ep_ptr = (nd_ep_t*) calloc(1, sizeof(*nd_ep_ptr));
	if (!nd_ep_ptr)
		return -FI_ENOMEM;

	nd_ep_ptr->fid.fid.fclass = FI_CLASS_EP;
	nd_ep_ptr->fid.fid.context = context;
	nd_ep_ptr->fid.fid.ops = &ofi_nd_fi_ops;
	nd_ep_ptr->fid.ops = &ofi_nd_ep_ops;
	nd_ep_ptr->fid.cm = &ofi_nd_cm_ops;
	nd_ep_ptr->fid.msg = &ofi_nd_ep_msg;
	nd_ep_ptr->fid.rma = &ofi_nd_ep_rma;
	nd_ep_ptr->domain = domain;
	nd_ep_ptr->connector = NULL;
	nd_ep_ptr->qp = NULL;
	nd_ep_ptr->cq = NULL;
	nd_ep_ptr->info = fi_dupinfo(info);

	HRESULT hr = nd_ep_ptr->domain->adapter->lpVtbl->CreateConnector(nd_ep_ptr->domain->adapter,
						&IID_IND2Connector,
						nd_ep_ptr->domain->adapter_file,
						(void**)&nd_ep_ptr->connector);

	if (FAILED(hr))
	{
		ofi_nd_ep_close(&nd_ep_ptr->fid.fid);
		return H2F(hr);
	}

	hr = nd_ep_ptr->connector->lpVtbl->Bind(nd_ep_ptr->connector,
					 &nd_ep_ptr->domain->addr.addr,
					 (ULONG)ofi_sizeofaddr(&nd_ep_ptr->domain->addr.addr));
	if (FAILED(hr))
	{
		ofi_nd_ep_close(&nd_ep_ptr->fid.fid);
		return H2F(hr);
	}

	nd_ep_ptr->fid.cm->connect = ofi_nd_ep_connect;

	hr = nd_ep_ptr->domain->adapter->lpVtbl->CreateCompletionQueue(
		nd_ep_ptr->domain->adapter, &IID_IND2CompletionQueue,
		nd_ep_ptr->domain->adapter_file,
		nd_ep_ptr->domain->ainfo.MaxCompletionQueueDepth, 0, 0,
		(void**)&nd_ep_ptr->cq);

	if (FAILED(hr))
	{
		ofi_nd_ep_close(&nd_ep_ptr->fid.fid);
		return H2F(hr);
	}

	*ep_fid = &nd_ep_ptr->fid;

	return FI_SUCCESS;
}

static int ofi_nd_ep_control(struct fid *fid, int command, void *arg)
{
	int ofi_nd_ep_control_enter = 0;
	if (fid->fclass != FI_CLASS_EP || command != FI_ENABLE)
		return -FI_EINVAL;

	nd_ep_t *nd_ep_ptr = container_of(fid, nd_ep_t, fid.fid);
	if (nd_ep_ptr->qp)
		return FI_SUCCESS; /* already enabled */

	HRESULT hr = nd_ep_ptr->domain->adapter->lpVtbl->CreateQueuePair(
		nd_ep_ptr->domain->adapter, &IID_IND2QueuePair,
		(IUnknown*)nd_ep_ptr->cq,
		(IUnknown*)nd_ep_ptr->cq,
		nd_ep_ptr,
		nd_ep_ptr->domain->ainfo.MaxReceiveQueueDepth,
		nd_ep_ptr->domain->ainfo.MaxInitiatorQueueDepth,
		nd_ep_ptr->domain->ainfo.MaxReceiveSge,
		nd_ep_ptr->domain->ainfo.MaxInitiatorSge,
		0, (void**)&nd_ep_ptr->qp);

	if (FAILED(hr))
		return H2F(hr);

	return FI_SUCCESS;
}

static int ofi_nd_ep_close(struct fid *fid)
{
	return -FI_ENOSYS;
}

static int ofi_nd_ep_connect(struct fid_ep *pep, const void *addr,
			     const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

static int ofi_nd_ep_accept(struct fid_ep *pep, const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

static int ofi_nd_ep_getname(fid_t fid, void *addr, size_t *addrlen)
{
	return -FI_ENOSYS;
}

static int ofi_nd_ep_bind(fid_t pep, fid_t bfid, uint64_t flags)
{
	if (pep->fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	nd_ep_t *ep = container_of(pep, nd_ep_t, fid.fid);

	switch (bfid->fclass)
	{
	case FI_CLASS_EQ:
		ep->eq = container_of(bfid, nd_eq_t, fid.fid);
		return FI_SUCCESS;
	case FI_CLASS_CQ:
		if (flags & FI_TRANSMIT) {
			ep->cq_send = container_of(bfid, nd_cq_t, fid.fid);
			ep->send_flags = flags;
		}
		if (flags & FI_RECV) {
			ep->cq_recv = container_of(bfid, nd_cq_t, fid.fid);
			ep->recv_flags = flags;
		}
		if (flags & FI_REMOTE_READ || flags & FI_REMOTE_WRITE)
			return -FI_EBADFLAGS;
		return FI_SUCCESS;
	default:
		ND_LOG_WARN(FI_LOG_EP_CTRL,
			   "ofi_nd_ep_bind: unknown bind class: %d",
			   (int)bfid->fclass);
	}

	return -FI_EINVAL;
}

static int ofi_nd_ep_shutdown(struct fid_ep *pep, uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_ep_cancel(fid_t fid, void *context)
{
	return -FI_ENOSYS;
}

#endif /* _WIN32 */

