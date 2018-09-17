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

#include <ws2spi.h>
#include <winsock2.h>
#include <windows.h>

#include "netdir.h"

#include "ofi.h"
#include "ofi_osd.h"
#include "ofi_util.h"

#include "netdir_log.h"
#include "netdir_misc.h"

static struct fi_ops_cm ofi_nd_cm_ops;
static struct fi_ops_ep ofi_nd_pep_ops;
static struct fi_ops ofi_nd_fi_ops;

int ofi_nd_passive_endpoint(struct fid_fabric *fabric, struct fi_info *info,
			    struct fid_pep **ppep, void *context)
{
	OFI_UNUSED(context);
	OFI_UNUSED(fabric);

	assert(info);
	assert(fabric);
	assert(fabric->fid.fclass == FI_CLASS_FABRIC);

	nd_pep_t *pep = (nd_pep_t*)calloc(1, sizeof(*pep));
	if (!pep)
		return -FI_ENOMEM;

	nd_pep_t def = {
		.fid = {
			.fid = {
				.fclass = FI_CLASS_PEP,
				.context = context,
				.ops = &ofi_nd_fi_ops
			},
			.ops = &ofi_nd_pep_ops,
			.cm = &ofi_nd_cm_ops
		},
		.info = fi_dupinfo(info)
	};

	*pep = def;
	*ppep = &pep->fid;

	return FI_SUCCESS;
}

static int ofi_nd_pep_getname(fid_t fid, void *addr, size_t *addrlen)
{
	assert(fid && fid->fclass == FI_CLASS_PEP);

	if (fid->fclass != FI_CLASS_PEP)
		return -FI_EINVAL;

	HRESULT hr;
	ULONG len = (ULONG)*addrlen;
	nd_pep_t *pep = container_of(fid, nd_pep_t, fid.fid);

	if (!pep->listener)
		return -FI_EOPBADSTATE;

	hr = pep->listener->lpVtbl->GetLocalAddress(pep->listener,
						    (struct sockaddr *)addr,
						    &len);

	if (*addrlen < len) {
		ND_LOG_INFO(FI_LOG_EP_CTRL,
			"Provided buffer (size = %"PRIu64") is too small, required = %"PRIu64,
			addrlen, len);
		*addrlen = (size_t)len;
		return -FI_ETOOSMALL;
	}
	*addrlen = (size_t)len;

	return H2F(hr);
}

static int ofi_nd_pep_close(struct fid *fid)
{
	assert(fid);
	assert(fid->fclass == FI_CLASS_PEP);

	nd_pep_t *pep = container_of(fid, nd_pep_t, fid.fid);

	int ref = 0;
	if (pep->listener) {
		ref = (int)pep->listener->lpVtbl->Release(pep->listener);
		ND_LOG_DEBUG(FI_LOG_EP_CTRL, "pep->listener ref count: %d\n", ref);
	}
	if (pep->adapter) {
		ref = (int)pep->adapter->lpVtbl->Release(pep->adapter);
		ND_LOG_DEBUG(FI_LOG_EP_CTRL, "pep->adapter ref count: %d\n", ref);
	}
	if (pep->adapter_file && pep->adapter_file != INVALID_HANDLE_VALUE)
		CloseHandle(pep->adapter_file);
	if (pep->info)
		fi_freeinfo(pep->info);

	free(pep);

	return FI_SUCCESS;
}

typedef struct nd_pep_connreq {
	nd_event_base_t		base;
	nd_eq_t		*eq;
	struct fi_info		*info;
	IND2Connector		*connector;
	fid_t			fid;
} nd_pep_connreq_t;

static void ofi_nd_pep_connreq_free(nd_event_base_t *base)
{
	assert(base);

	nd_pep_connreq_t *connreq = container_of(base, nd_pep_connreq_t, base);
	if (connreq->connector)
		connreq->connector->lpVtbl->Release(connreq->connector);
	free(connreq);
}

static inline void ofi_nd_eq_free_event(nd_eq_event_t *ev)
{
	assert(ev);

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

static void ofi_nd_pep_connreq(nd_event_base_t *base, DWORD bytes)
{
	assert(base);
	OFI_UNUSED(bytes);

	HRESULT hr;
	ULONG len;
	nd_pep_connreq_t *connreq = container_of(base, nd_pep_connreq_t, base);
	nd_eq_event_t *err = 0;

	assert(connreq->connector);
	assert(connreq->eq);
	assert(connreq->fid);
	assert(connreq->info);

	nd_eq_event_t *ev = (nd_eq_event_t*)malloc(sizeof(*ev));
	if (!ev)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate event\n");
		hr = ND_NO_MEMORY;
		goto fn_fail_ev;
	}
	memset(ev, 0, sizeof(*ev));

	ev->eq_event = FI_CONNREQ;

	struct fi_eq_cm_entry *cmev = (struct fi_eq_cm_entry*)&ev->operation;
	cmev->fid = connreq->fid;
	cmev->info = fi_dupinfo(connreq->info);
	if (!cmev->info)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to copy info\n");
		hr = ND_NO_MEMORY;
		goto fn_fail;
	}

	nd_connreq_t *handle = (nd_connreq_t*)malloc(sizeof(*handle));
	if (!handle)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate handle\n");
		hr = ND_NO_MEMORY;
		goto fn_fail;
	}
	memset(handle, 0, sizeof(*handle));
	handle->handle.fclass = FI_CLASS_CONNREQ;
	handle->connector = connreq->connector;
	handle->connector->lpVtbl->AddRef(handle->connector);
	cmev->info->handle = &handle->handle;

	hr = connreq->connector->lpVtbl->GetPrivateData(
		connreq->connector, NULL, &len);
	if (FAILED(hr) && hr != ND_BUFFER_OVERFLOW)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to get private data\n");
		goto fn_fail_handle;
	}

	if (len)
	{
		ev->data = malloc(len);
		if (!ev->data)
		{
			ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate private data\n");
			ev->len = 0;
			goto fn_fail_handle;
		}

		hr = connreq->connector->lpVtbl->GetPrivateData(
			connreq->connector, ev->data, &len);
		if (FAILED(hr))
		{
			ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to copy private data\n");
			free(ev->data);
			ev->len = 0;
			goto fn_fail_handle;
		}
	}
	ev->len = (size_t)len;

	ofi_nd_eq_push(connreq->eq, ev);
	ofi_nd_pep_connreq_free(&connreq->base);
	return;

fn_fail_handle:
	handle->connector->lpVtbl->Release(handle->connector);
	free(handle);
fn_fail:
	ofi_nd_eq_free_event(ev);
fn_fail_ev:
	err = (struct nd_eq_event*)malloc(sizeof(*err));
	if (!err)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate error\n");
		return;
	}
	memset(err, 0, sizeof(*err));
	err->error.err = -H2F(hr);
	err->error.prov_errno = (int)hr;
	err->error.fid = connreq->fid;
	ofi_nd_eq_push_err(connreq->eq, err);
	ofi_nd_pep_connreq_free(&connreq->base);
}

static void ofi_nd_pep_connreq_err(nd_event_base_t *base, DWORD err,
				   DWORD bytes)
{
}

static nd_event_base_t nd_pep_connreq_base_def = {
	.free = ofi_nd_pep_connreq_free,
	.event_cb = ofi_nd_pep_connreq,
	.err_cb = ofi_nd_pep_connreq_err
};

void CALLBACK domain_io_cb(DWORD err, DWORD bytes, LPOVERLAPPED ov)
{
	assert(ov);

	nd_event_base_t *base = container_of(ov, nd_event_base_t, ov);

	ND_LOG_DEBUG(FI_LOG_EP_CTRL,
		"IO callback: err: %s, bytes: %d\n",
		ofi_nd_error_str(err), bytes);

	if (err)
	{
		assert(base->err_cb);
		base->err_cb(base, bytes, err);
	}
	else
	{
		assert(base->event_cb);
		base->event_cb(base, bytes);
	}
}

static int ofi_nd_pep_listen(struct fid_pep *ppep)
{
	assert(ppep);

	int res = FI_SUCCESS;
	HRESULT hr;

	if (ppep->fid.fclass != FI_CLASS_PEP)
		return -FI_EINVAL;

	nd_pep_t *pep = container_of(ppep, nd_pep_t, fid);

	assert(pep->info);
	assert(pep->info->domain_attr);
	assert(pep->info->domain_attr->name);

	struct sockaddr* addr;

	if (!pep->adapter)
	{
		struct sockaddr* listen_addr = NULL;
		size_t listen_addr_len = 0;

		res = ofi_nd_lookup_adapter(pep->info->domain_attr->name,
					    &pep->adapter, &addr);
		if (res != FI_SUCCESS)
			return res;
		assert(pep->adapter);

		hr = pep->adapter->lpVtbl->CreateOverlappedFile(pep->adapter,
								&pep->adapter_file);
		if (FAILED(hr))
			return H2F(hr);
		assert(pep->adapter_file &&
			      pep->adapter_file != INVALID_HANDLE_VALUE);

		BindIoCompletionCallback(pep->adapter_file, domain_io_cb, 0);

		hr = pep->adapter->lpVtbl->CreateListener(pep->adapter,
							  &IID_IND2Listener,
							  pep->adapter_file,
							  (void**)&pep->listener);
		if (FAILED(hr))
			return H2F(hr);
		assert(pep->listener);

		if (pep->info->src_addr) {
			/* uses address that is specified in fi_info */
			listen_addr = pep->info->src_addr;
			listen_addr_len = pep->info->src_addrlen;
		}
		else {
			/* uses address on which provider are open */
			listen_addr = addr;
			listen_addr_len = ofi_sizeofaddr(addr);
		}

		hr = pep->listener->lpVtbl->Bind(pep->listener,
					listen_addr,
					(ULONG)sizeof(*listen_addr));
		if (FAILED(hr))
			return H2F(hr);

		hr = pep->listener->lpVtbl->Listen(pep->listener, 0);
		if (FAILED(hr))
			return H2F(hr);
	}
	assert(pep->adapter);

	nd_pep_connreq_t *conn = (nd_pep_connreq_t*)malloc(sizeof(*conn));
	if (!conn)
		return -FI_ENOMEM;
	memset(conn, 0, sizeof(*conn));

	conn->base = nd_pep_connreq_base_def;

	hr = pep->adapter->lpVtbl->CreateConnector(pep->adapter,
						   &IID_IND2Connector,
						   pep->adapter_file,
						   (void**)&conn->connector);
	if (FAILED(hr))
		return H2F(hr);

	conn->eq = pep->eq;
	conn->info = pep->info;
	conn->fid = &pep->fid.fid;

	hr = pep->listener->lpVtbl->GetConnectionRequest(pep->listener,
		(IUnknown*)conn->connector,
		&conn->base.ov);
	if (FAILED(hr)) {
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to get connection request\n");
	}

	return H2F(hr);
}

static int ofi_nd_pep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	OFI_UNUSED(flags);

	if (fid->fclass != FI_CLASS_PEP)
		return -FI_EINVAL;
	if (bfid->fclass != FI_CLASS_EQ)
		return -FI_EINVAL;

	nd_pep_t *pep = container_of(fid, nd_pep_t, fid.fid);
	nd_eq_t *eq = container_of(bfid, nd_eq_t, fid.fid);

	pep->eq = eq;

	return FI_SUCCESS;
}

static int ofi_nd_pep_reject(struct fid_pep *ppep, fid_t handle,
			     const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

static int ofi_nd_pep_getopt(struct fid *ep, int level, int optname,
			void *optval, size_t *optlen)
{
	return -FI_ENOSYS;
}

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_pep_close,
	.bind = ofi_nd_pep_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fid ofi_nd_fid = {
	.fclass = FI_CLASS_PEP,
	.context = NULL,
	.ops = &ofi_nd_fi_ops
};

static struct fi_ops_cm ofi_nd_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = ofi_nd_pep_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = ofi_nd_pep_listen,
	.accept = fi_no_accept,
	.reject = ofi_nd_pep_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};

static struct fi_ops_ep ofi_nd_pep_ops = {
	.size = sizeof(ofi_nd_pep_ops),
	.cancel = fi_no_cancel,
	.getopt = ofi_nd_pep_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

#endif /* _WIN32 */

