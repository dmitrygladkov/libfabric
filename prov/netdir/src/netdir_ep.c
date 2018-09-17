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

extern struct fi_ops_msg ofi_nd_ep_msg;
extern struct fi_ops_rma ofi_nd_ep_rma;

static struct fi_ops ofi_nd_fi_ops;
static struct fi_ops_cm ofi_nd_cm_ops;
static struct fi_ops_ep ofi_nd_ep_ops;

static int ofi_nd_ep_accept(struct fid_ep *pep, const void *param, size_t paramlen);
static int ofi_nd_ep_connect(struct fid_ep *pep, const void *addr,
			     const void *param, size_t paramlen);
static int ofi_nd_ep_close(struct fid *fid);
static int ofi_nd_ep_shutdown(struct fid_ep *pep, uint64_t flags);

static void ofi_nd_ep_disconnected_free(nd_event_base_t* base)
{
	OFI_UNUSED(base);
}

static void ofi_nd_ep_disconnected(nd_event_base_t* base, DWORD bytes)
{
	OFI_UNUSED(bytes);

	nd_ep_t *ep = container_of(base, nd_ep_t, disconnect_ov);
	assert(ep->fid.fid.fclass == FI_CLASS_EP);

	ep->connected = 0;
	
	nd_eq_event_t *ev = (nd_eq_event_t*)malloc(sizeof(*ev));
	if (!ev)
		return;

	memset(ev, 0, sizeof(*ev));
	struct fi_eq_cm_entry *cm = (struct fi_eq_cm_entry*)&ev->operation;
	ev->eq_event = FI_SHUTDOWN;
	cm->fid = &ep->fid.fid;
	ofi_nd_eq_push(ep->eq, ev);

	//ofi_nd_ep_shutdown(&ep->fid, 0);
}

static void ofi_nd_ep_disconnected_err(nd_event_base_t* base, DWORD bytes,
				       DWORD err)
{
	if (err == STATUS_CONNECTION_DISCONNECTED)
	{
		ofi_nd_ep_disconnected(base, bytes);
	}
	else
	{
		nd_ep_t *ep = container_of(base, nd_ep_t, disconnect_ov);

		nd_eq_event_t *ev = (nd_eq_event_t*)malloc(sizeof(*ev));
		if (!ev)
			return;

		memset(ev, 0, sizeof(*ev));
		ev->eq_event = FI_SHUTDOWN;
		ev->error.err = H2F(err);
		ev->error.prov_errno = err;
		ev->error.fid = &ep->fid.fid;
		ofi_nd_eq_push_err(ep->eq, ev);
	}
}

int ofi_nd_endpoint(struct fid_domain *pdomain, struct fi_info *info,
	struct fid_ep **ep_fid, void *context)
{
	assert(info);
	assert(pdomain);
	assert(pdomain->fid.fclass == FI_CLASS_DOMAIN);

	HRESULT hr;

	nd_domain_t *domain = container_of(pdomain, nd_domain_t, fid);
	nd_connreq_t *connreq = 0;
	nd_ep_t *ep = (nd_ep_t*) calloc(1, sizeof(*ep));
	if (!ep)
		return -FI_ENOMEM;

	nd_ep_t def = {
		.fid = {
			.fid = {
				.fclass = FI_CLASS_EP,
				.context = context,
				.ops = &ofi_nd_fi_ops
			},
			.ops = &ofi_nd_ep_ops,
			.cm = &ofi_nd_cm_ops,
			.msg = &ofi_nd_ep_msg,
			.rma = &ofi_nd_ep_rma
		},
		.info = fi_dupinfo(info),
		.domain = domain,
		.eq = domain->eq,
		.disconnect_ov = {
			.free = ofi_nd_ep_disconnected_free,
			.event_cb = ofi_nd_ep_disconnected,
			.err_cb = ofi_nd_ep_disconnected_err
		}
	};

	*ep = def;

	/* Initialzie flow control counter */
	ep->send_op.used_counter = 0;
	InitializeCriticalSection(&ep->send_op.send_lock);

	if (info->handle)
	{
		assert(info->handle->fclass == FI_CLASS_CONNREQ);
		if (info->handle->fclass != FI_CLASS_CONNREQ)
			return -FI_EINVAL;
		connreq = container_of(info->handle, nd_connreq_t,
				       handle);
	}

	InitializeCriticalSection(&ep->prepost_lock);

	assert(domain->adapter);

	if (connreq)
	{
		assert(connreq->connector);
		ep->connector = connreq->connector;
		free(connreq);
		ep->fid.cm->accept = ofi_nd_ep_accept;
	}
	else
	{
		hr = domain->adapter->lpVtbl->CreateConnector(domain->adapter,
							&IID_IND2Connector,
							domain->adapter_file,
							(void**)&ep->connector);
		if (FAILED(hr))
			goto fn_fail;

		hr = ep->connector->lpVtbl->Bind(ep->connector,
						 &domain->addr.addr,
						 (ULONG)ofi_sizeofaddr(&domain->addr.addr));
		if (FAILED(hr))
			goto fn_fail;

		ep->fid.cm->connect = ofi_nd_ep_connect;
	}

	dlist_insert_tail(&ep->entry, &domain->ep_list);

	/* do NOT create real ND endpoint here: we could not know
	how CQ will be attached here */

	*ep_fid = &ep->fid;
	/* hr = ofi_nd_unexp_init(ep); */

	return 0;

fn_fail:
	ofi_nd_ep_close(&domain->fid.fid);
	ND_LOG_WARN(FI_LOG_EP_CTRL, ofi_nd_strerror((DWORD)hr, NULL));
	return H2F(hr);
}

static int ofi_nd_ep_control(struct fid *fid, int command, void *arg)
{
	OFI_UNUSED(arg);

	assert(fid->fclass == FI_CLASS_EP);

	HRESULT hr;

	if (command != FI_ENABLE)
		return -FI_EINVAL;

	nd_ep_t *ep = container_of(fid, nd_ep_t, fid.fid);

	if (ep->qp)
		return FI_SUCCESS; /* already enabled */

	hr = ep->domain->adapter->lpVtbl->CreateQueuePair(
		ep->domain->adapter, &IID_IND2QueuePair,
		(IUnknown*)ep->domain->cq,
		(IUnknown*)ep->domain->cq,
		ep,
		ep->domain->ainfo.MaxReceiveQueueDepth,
		ep->domain->ainfo.MaxInitiatorQueueDepth,
		ep->domain->ainfo.MaxReceiveSge,
		ep->domain->ainfo.MaxInitiatorSge,
		0, (void**)&ep->qp);
	if (FAILED(hr))
		return H2F(hr);

	/* Initialzie unexpected functionality */
	/* it's better not to
	InitializeCriticalSection(&ep->unexpected.unexp_lock);
	ofi_nd_unexp_run(ep);
	*/

	return FI_SUCCESS;
}

static int ofi_nd_ep_close(struct fid *fid)
{
	ND_LOG_DEBUG(FI_LOG_EP_CTRL, "closing ep\n");

	assert(fid->fclass == FI_CLASS_EP);

	nd_ep_t *ep = container_of(fid, nd_ep_t, fid.fid);

	ofi_nd_ep_shutdown(&ep->fid, 0);

	int res;
	if (ep->connector)
	{
		res = (int)ep->connector->lpVtbl->Release(ep->connector);
		ND_LOG_DEBUG(FI_LOG_EP_CTRL, "ep->connector ref count: %d\n", res);
	}

	if (ep->qp)
	{
		res = (int)ep->qp->lpVtbl->Release(ep->qp);
		ND_LOG_DEBUG(FI_LOG_EP_CTRL, "ep->qp ref count: %d\n", res);
	}

	if (ep->info)
		fi_freeinfo(ep->info);

	DeleteCriticalSection(&ep->prepost_lock);
	/* Release Critical Section for unexpected events */
	/* DeleteCriticalSection(&ep->unexpected.unexp_lock); */

	/* Retrieve this endpoint from domain EP list */
	dlist_remove(&ep->entry);
	DeleteCriticalSection(&ep->send_op.send_lock);
	free(ep);
	ep = NULL;

	return FI_SUCCESS;
}

typedef struct nd_ep_connect {
	nd_event_base_t		base;
	nd_ep_t		*ep;
	nd_eq_t		*eq;
	IND2Connector		*connector;
	int			active;
} nd_ep_connect_t;

typedef struct nd_ep_completed {
	nd_event_base_t	base;
	nd_ep_t		*ep;
	nd_eq_t		*eq;
	IND2Connector		*connector;
} nd_ep_completed_t;

static void ofi_nd_ep_completed_free(nd_event_base_t *base)
{
	assert(base);

	nd_ep_completed_t *compl = container_of(base, nd_ep_completed_t, base);
	assert(compl->connector);
	compl->connector->lpVtbl->Release(compl->connector);
	free(compl);
}

static void ofi_nd_ep_completed(nd_event_base_t *base, DWORD bytes)
{
	OFI_UNUSED(bytes);
	assert(base);
	assert(base->free);

	nd_ep_completed_t *compl = container_of(base, nd_ep_completed_t, base);
	assert(compl->connector);

	base->free(base);
}

static void ofi_nd_ep_completed_err(nd_event_base_t *base, DWORD bytes,
				    DWORD error)
{
	OFI_UNUSED(bytes);
	assert(base);
	assert(base->free);

	nd_ep_completed_t *compl = container_of(base, nd_ep_completed_t, base);

	nd_eq_event_t *err = (nd_eq_event_t*)malloc(sizeof(*err));
	if (!err)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL,
			   "failed to allocate error event\n");
		base->free(base);
		return;
	}

	memset(err, 0, sizeof(*err));
	err->error.err = -H2F(error);
	err->error.prov_errno = (int)error;
	err->error.fid = &compl->ep->fid.fid;
	ofi_nd_eq_push_err(compl->eq, err);
}

static void ofi_nd_ep_accepted_free(nd_event_base_t *base)
{
	assert(base);

	nd_ep_connect_t *connect = container_of(base, nd_ep_connect_t, base);
	if (connect->connector)
		connect->connector->lpVtbl->Release(connect->connector);
	free(connect);
}

static void ofi_nd_ep_accepted(nd_event_base_t *base, DWORD bytes)
{
	assert(base);
	OFI_UNUSED(bytes);

	HRESULT hr;
	ULONG len = 0;
	nd_ep_connect_t *connect = container_of(base, nd_ep_connect_t, base);
	nd_eq_event_t *err;
	nd_ep_completed_t *compl = NULL;

	assert(connect->connector);
	assert(connect->ep);
	assert(connect->eq);

	nd_eq_event_t *ev = (nd_eq_event_t*)malloc(sizeof(*ev));
	if (!ev)
	{
		hr = ND_NO_MEMORY;
		goto fn_fail_ev;
	}
	memset(ev, 0, sizeof(*ev));
	ev->eq_event = FI_CONNECTED;

	hr = connect->connector->lpVtbl->GetPrivateData(
		connect->connector, NULL, &len);

	if (connect->active)
	{
		hr = connect->connector->lpVtbl->GetPrivateData(
			connect->connector, NULL, &len);

		if (FAILED(hr) && hr != ND_BUFFER_OVERFLOW)
		{
			ND_LOG_WARN(FI_LOG_EP_CTRL,
				   "failed to get connection data\n");
			goto fn_fail_data;
		}

		if (len)
		{
			ev->data = malloc(len);
			if (!ev->data)
			{
				ND_LOG_WARN(FI_LOG_EP_CTRL,
					   "failed to allocate connection data\n");
				hr = ND_NO_MEMORY;
				ev->len = 0;
				goto fn_fail_data;
			}

			hr = connect->connector->lpVtbl->GetPrivateData(
				connect->connector, ev->data, &len);
			if (FAILED(hr))
			{
				ND_LOG_WARN(FI_LOG_EP_CTRL,
					   "failed to copy connection data\n");
				free(ev->data);
				ev->len = 0;
				goto fn_fail_data;
			}
		}
		ev->len = (size_t)len;

		compl = (nd_ep_completed_t *)malloc(sizeof(*compl));
		if (!compl)
		{
			ND_LOG_WARN(FI_LOG_EP_CTRL,
				   "failed to allocate connection-complete event\n");
			goto fn_fail_data;
		}
		memset(compl, 0 , sizeof(*compl));
		compl->base.event_cb = ofi_nd_ep_completed;
		compl->base.err_cb = ofi_nd_ep_completed_err;
		compl->base.free = ofi_nd_ep_completed_free;
		compl->ep = connect->ep;
		compl->eq = connect->eq;
		compl->connector = connect->connector;
		connect->connector->lpVtbl->AddRef(connect->connector);

		hr = connect->connector->lpVtbl->CompleteConnect(connect->connector,
								 &compl->base.ov);
		if (FAILED(hr))
		{
			ND_LOG_WARN(FI_LOG_EP_CTRL,
				   "failed to complete connection\n");
			free(compl);
			goto fn_fail_compl;
		}
	}

	ND_LOG_DEBUG(FI_LOG_EP_CTRL, "register disconnect notification: %p\n",
		    &connect->ep->disconnect_ov.ov);
	hr = connect->connector->lpVtbl->NotifyDisconnect(
		connect->connector, &connect->ep->disconnect_ov.ov);
	if (FAILED(hr))
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL,
			   "failed to notify disconnect\n");
		free(compl);
		goto fn_fail_compl;
	}

	struct fi_eq_cm_entry *cm = (struct fi_eq_cm_entry*)&ev->operation;
	cm->fid = &connect->ep->fid.fid;
	ofi_nd_eq_push(connect->eq, ev);
	ofi_nd_ep_accepted_free(&connect->base);
	/* TODO resolve segmentation fault below */
	/* connect->ep->connected = 1; */
	return;

fn_fail_compl:
	if (len) {
		free(ev->data);
		ev->len = 0;
	}
	connect->connector->lpVtbl->Release(connect->connector);

fn_fail_data:
	free(ev);

fn_fail_ev:
	err = (struct nd_eq_event*)malloc(sizeof(*err));
	if (!err) {
		ND_LOG_WARN(FI_LOG_EP_CTRL,
			   "failed to allocate error event\n");
		ofi_nd_ep_accepted_free(&connect->base);
		return;
	}
	memset(err, 0, sizeof(*err));
	err->error.err = -H2F(hr);
	err->error.prov_errno = (int)hr;
	err->error.fid = &connect->ep->fid.fid;
	ofi_nd_eq_push_err(connect->eq, err);
	ofi_nd_ep_accepted_free(&connect->base);
}

static void ofi_nd_ep_rejected(nd_event_base_t *base, DWORD bytes, DWORD error)
{
	assert(0);
}

static int ofi_nd_ep_connect(struct fid_ep *pep, const void *addr,
			     const void *param, size_t paramlen)
{
	assert(pep->fid.fclass == FI_CLASS_EP);

	nd_ep_t *ep = container_of(pep, nd_ep_t, fid);

	if (!addr)
		return -FI_EINVAL;

	int res = fi_enable(&ep->fid);
	if (res)
		return res;

	assert(ep->connector);
	assert(ep->qp);

	HRESULT hr;

	nd_ep_connect_t *wait = (nd_ep_connect_t*)malloc(sizeof(*wait));
	if (!wait)
		return -FI_ENOMEM;

	memset(wait, 0, sizeof(*wait));
	wait->ep = ep;
	wait->eq = ep->eq;
	wait->connector = ep->connector;
	wait->base.event_cb = ofi_nd_ep_accepted;
	wait->base.err_cb = ofi_nd_ep_rejected;
	wait->base.free = ofi_nd_ep_accepted_free;
	wait->active = 1;
	ep->connector->lpVtbl->AddRef(ep->connector);

	hr = ep->connector->lpVtbl->Connect(
		ep->connector, (IUnknown*)ep->qp,
		(struct sockaddr*)addr, (ULONG)ofi_sizeofaddr((struct sockaddr*)addr),
		ep->domain->ainfo.MaxInboundReadLimit,
		ep->domain->ainfo.MaxOutboundReadLimit,
		param, (ULONG)paramlen, &wait->base.ov);
	return H2F(hr);
}

static int ofi_nd_ep_accept(struct fid_ep *pep, const void *param, size_t paramlen)
{
	assert(pep->fid.fclass == FI_CLASS_EP);

	nd_ep_t *ep = container_of(pep, nd_ep_t, fid);

	int res = fi_enable(&ep->fid);
	if (res)
		return res;

	assert(ep->connector);
	assert(ep->qp);

	HRESULT hr;

	nd_ep_connect_t *accept = (nd_ep_connect_t*)malloc(sizeof(*accept));
	if (!accept)
		return -FI_ENOMEM;

	memset(accept, 0, sizeof(*accept));
	accept->ep = ep;
	accept->eq = ep->eq;
	accept->connector = ep->connector;
	accept->base.event_cb = ofi_nd_ep_accepted;
	accept->base.err_cb = ofi_nd_ep_rejected;
	accept->base.free = ofi_nd_ep_accepted_free;
	accept->connector->lpVtbl->AddRef(accept->connector);

	ND_LOG_DEBUG(FI_LOG_EP_CTRL, "sending accept message\n");

	hr = ep->connector->lpVtbl->Accept(
		ep->connector, (IUnknown*)ep->qp,
		ep->domain->ainfo.MaxInboundReadLimit,
		ep->domain->ainfo.MaxOutboundReadLimit,
		param, (ULONG)paramlen, &accept->base.ov);
	if (FAILED(hr))
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to send accept message: %x\n",
			   hr);

	return H2F(hr);
}

static int ofi_nd_ep_getname(fid_t fid, void *addr, size_t *addrlen)
{
	return -FI_ENOSYS;
}

static int ofi_nd_ep_bind(fid_t pep, fid_t bfid, uint64_t flags)
{
	assert(pep->fclass == FI_CLASS_EP);

	if (pep->fclass != FI_CLASS_EP)
		return -FI_EINVAL;

	nd_ep_t *ep = container_of(pep, nd_ep_t, fid.fid);

	switch (bfid->fclass)
	{
	case FI_CLASS_EQ:
		ep->eq = container_of(bfid, nd_eq_t, fid.fid);
		return FI_SUCCESS;
	case FI_CLASS_CQ:
		if (flags & FI_TRANSMIT)
		{
			ep->cq_send = container_of(bfid, nd_cq_t, fid.fid);
			ep->send_flags = flags;
		}
		if (flags & FI_RECV)
		{
			ep->cq_recv = container_of(bfid, nd_cq_t, fid.fid);
			ep->recv_flags = flags;
		}
		if (flags & FI_REMOTE_READ || flags & FI_REMOTE_WRITE)
			return -FI_EBADFLAGS;
		return FI_SUCCESS;
	case FI_CLASS_CNTR:
		if (flags & FI_SEND)
			ep->cntr_send = container_of(bfid, nd_cntr_t, fid.fid);
		if (flags & FI_RECV)
			ep->cntr_recv = container_of(bfid, nd_cntr_t, fid.fid);
		if (flags & FI_READ)
			ep->cntr_read = container_of(bfid, nd_cntr_t, fid.fid);
		if (flags & FI_WRITE)
			ep->cntr_write = container_of(bfid, nd_cntr_t, fid.fid);
		if (flags & FI_REMOTE_READ || flags & FI_REMOTE_WRITE)
			return -FI_EBADFLAGS;
		return FI_SUCCESS;
	case FI_CLASS_SRX_CTX:
		ep->srx = container_of(bfid, nd_srx_t, fid.fid);
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

#endif /* _WIN32 */

