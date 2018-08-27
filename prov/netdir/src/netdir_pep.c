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

int ofi_nd_passive_endpoint(struct fid_fabric *fabric, struct fi_info *info,
			    struct fid_pep **ppep, void *context);
static int ofi_nd_pep_getname(fid_t fid, void *addr, size_t *addrlen);
static int ofi_nd_pep_close(struct fid *fid);
static int ofi_nd_pep_listen(struct fid_pep *ppep);
static int ofi_nd_pep_bind(struct fid *fid, struct fid *bfid, uint64_t flags);
static int ofi_nd_pep_reject(struct fid_pep *ppep, fid_t handle,
			     const void *param, size_t paramlen);
static int ofi_nd_pep_getopt(struct fid *ep, int level, int optname,
			void *optval, size_t *optlen);

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

typedef struct nd_pep {
	struct fid_pep fid;
	struct fi_info *info;
	nd_eq_t *eq;
	IND2Adapter *adapter;
	IND2Listener *listener;
	HANDLE adapter_file;
} nd_pep_t;

int ofi_nd_passive_endpoint(struct fid_fabric *fabric, struct fi_info *info,
			    struct fid_pep **ppep, void *context)
{
	if (!ppep)
		return -FI_EINVAL;

	if (!info || !fabric || fabric->fid.fclass != FI_CLASS_FABRIC)
		return -FI_EINVAL;

	nd_pep_t *pep_ptr = (nd_pep_t*)calloc(1, sizeof(*pep_ptr));
	if (!pep_ptr)
		return -FI_ENOMEM;

	pep_ptr->fid.fid.fclass = FI_CLASS_PEP;
	pep_ptr->fid.fid.context = context;
	pep_ptr->fid.fid.ops = &ofi_nd_fi_ops;
	pep_ptr->fid.ops = &ofi_nd_pep_ops;
	pep_ptr->fid.cm = &ofi_nd_cm_ops;
	pep_ptr->info = fi_dupinfo(info);
	pep_ptr->adapter = NULL;
	pep_ptr->listener = NULL;
	pep_ptr->adapter_file = INVALID_HANDLE_VALUE;

	*ppep = &pep_ptr->fid;

	return FI_SUCCESS;
}

static int ofi_nd_pep_getname(fid_t fid, void *addr, size_t *addrlen)
{
	if (fid->fclass != FI_CLASS_PEP || !addrlen)
		return -FI_EINVAL;

	nd_pep_t *pep = container_of(fid, nd_pep_t, fid.fid);
	if (!pep->listener)
		return -FI_EOPBADSTATE;

	ULONG len = (ULONG)*addrlen;
	HRESULT hr = pep->listener->lpVtbl->GetLocalAddress(pep->listener,
						    (struct sockaddr *)addr,
						    &len);

	if (*addrlen < len)
	{
		*addrlen = (size_t)len;
		return -FI_ETOOSMALL;
	}
	*addrlen = (size_t)len;

	return H2F(hr);
}

static int ofi_nd_pep_close(struct fid *fid)
{
	nd_pep_t *pep = container_of(fid, nd_pep_t, fid.fid);

	int ref = 0;
	if (pep->listener)
	{
		ref = (int)pep->listener->lpVtbl->Release(pep->listener);
	}
	if (pep->adapter)
	{
		ref = (int)pep->adapter->lpVtbl->Release(pep->adapter);
	}

	if (pep->adapter_file && pep->adapter_file != INVALID_HANDLE_VALUE)
		CloseHandle(pep->adapter_file);

	if (pep->info)
		fi_freeinfo(pep->info);

	free(pep);

	return FI_SUCCESS;
}

typedef struct nd_pep_connreq {
	nd_event_base_t base;
	IND2Connector *connector;
	nd_eq_t *eq;
	fid_t fid;
	struct fi_info *info;
} nd_pep_connreq_t;

static void ofi_nd_pep_connreq_free(nd_event_base_t *base)
{
	nd_pep_connreq_t *connreq = container_of(base, nd_pep_connreq_t, base);
	if (connreq->connector)
		connreq->connector->lpVtbl->Release(connreq->connector);
	free(connreq);
}

static void ofi_nd_pep_connreq(nd_event_base_t *base_ptr, DWORD bytes)
{
	HRESULT hr = ERROR_SUCCESS;
	nd_pep_connreq_t *connreq_ptr = container_of(base_ptr, nd_pep_connreq_t, base);
	nd_eq_event_t *ev_ptr = (nd_eq_event_t *) calloc(1, sizeof(*ev_ptr));
	if (!ev_ptr)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate event\n");
		hr = ND_NO_MEMORY;

		nd_eq_event_t *err_ptr = (nd_eq_event_t *) calloc(1, sizeof(*err_ptr));
		if (!err_ptr)
		{
			ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate error\n");
			return;
		}

		err_ptr->error.err = -H2F(hr);
		err_ptr->error.prov_errno = (int)hr;
		err_ptr->error.fid = connreq_ptr->fid;
		ofi_nd_eq_push_err(connreq_ptr->eq, err_ptr);
		ofi_nd_pep_connreq_free(&connreq_ptr->base);
	}
	ev_ptr->eq_event = FI_CONNREQ;

	struct fi_eq_cm_entry *cmev = (struct fi_eq_cm_entry*)&ev_ptr->operation;
	cmev->fid = connreq_ptr->fid;
	cmev->info = fi_dupinfo(connreq_ptr->info);
	if (!cmev->info)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to copy info\n");
		hr = ND_NO_MEMORY;
		/* goto fn_fail; */
	}

	nd_connreq_t *handle = (nd_connreq_t*) calloc(1, sizeof(*handle));
	if (!handle)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate handle\n");
		hr = ND_NO_MEMORY;
		/* goto fn_fail; */
	}

	handle->handle.fclass = FI_CLASS_CONNREQ;
	handle->connector = connreq_ptr->connector;
	handle->connector->lpVtbl->AddRef(handle->connector);
	cmev->info->handle = &handle->handle;

	ULONG len = 0;
	hr = connreq_ptr->connector->lpVtbl->GetPrivateData(
		connreq_ptr->connector, NULL, &len);

	if (FAILED(hr) && hr != ND_BUFFER_OVERFLOW)
	{
		ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to get private data\n");
		/* goto fn_fail_handle; */
	}

	if (len)
	{
		ev_ptr->data = malloc(len);
		if (!ev_ptr->data)
		{
			ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to allocate private data\n");
			ev_ptr->len = 0;
			/* goto fn_fail_handle; */
		}

		hr = connreq_ptr->connector->lpVtbl->GetPrivateData(
			connreq_ptr->connector, ev_ptr->data, &len);
		if (FAILED(hr)) {
			ND_LOG_WARN(FI_LOG_EP_CTRL, "failed to copy private data\n");
			free(ev_ptr->data);
			ev_ptr->len = 0;
			/* goto fn_fail_handle; */
		}
	}
	ev_ptr->len = (size_t)len;

	ofi_nd_eq_push(connreq_ptr->eq, ev_ptr);
	ofi_nd_pep_connreq_free(&connreq_ptr->base);
}

static void ofi_nd_pep_connreq_err(nd_event_base_t *base_ptr, DWORD bytes, DWORD err)
{
}

static int ofi_nd_pep_listen(struct fid_pep *ppep)
{
	if (!ppep || ppep->fid.fclass != FI_CLASS_PEP)
		return -FI_EINVAL;

	nd_pep_t *pep = container_of(ppep, struct nd_pep, fid);

	HRESULT hr = ERROR_SUCCESS;
	if (!pep->adapter)
	{
		struct sockaddr *addr = NULL;
		struct sockaddr *listen_addr = NULL;
		size_t listen_addr_len = 0;

		int res = ofi_nd_lookup_adapter(pep->info->domain_attr->name,
					    &pep->adapter, &addr);
		if (res != FI_SUCCESS)
			return res;
		if (!pep->adapter)
			return -FI_ENODATA;

		hr = pep->adapter->lpVtbl->CreateOverlappedFile(pep->adapter,
								&pep->adapter_file);
		if (FAILED(hr))
			return H2F(hr);
		if (pep->adapter_file == INVALID_HANDLE_VALUE)
			return -FI_ENODATA;

		BindIoCompletionCallback(pep->adapter_file, domain_io_cb, 0);

		hr = pep->adapter->lpVtbl->CreateListener(pep->adapter,
				&IID_IND2Listener, pep->adapter_file, (void**)&pep->listener);
		if (FAILED(hr))
			return H2F(hr);
		if (!pep->listener)
			return -FI_ENODATA;

		/* use address where provider opened */
		listen_addr = addr;
		listen_addr_len = ofi_sizeofaddr(addr);

		hr = pep->listener->lpVtbl->Bind(pep->listener,
					listen_addr,
					(ULONG)sizeof(*listen_addr));
		if (FAILED(hr))
			return H2F(hr);

		hr = pep->listener->lpVtbl->Listen(pep->listener, 0);
		if (FAILED(hr))
			return H2F(hr);
	}

	nd_pep_connreq_t *connreq_ptr = (nd_pep_connreq_t*)calloc(1, sizeof(*connreq_ptr));
	if (!connreq_ptr)
		return -FI_ENOMEM;

	connreq_ptr->base.event_cb = ofi_nd_pep_connreq;
	connreq_ptr->base.error_cb = ofi_nd_pep_connreq_err; /* placeholder */

	hr = pep->adapter->lpVtbl->CreateConnector(pep->adapter,
			&IID_IND2Connector, pep->adapter_file, (void**)&connreq_ptr->connector);

	if (FAILED(hr))
		return H2F(hr);

	connreq_ptr->eq = pep->eq;
	connreq_ptr->info = pep->info;
	connreq_ptr->fid = &pep->fid.fid;

	hr = pep->listener->lpVtbl->GetConnectionRequest(pep->listener,
		(IUnknown*)connreq_ptr->connector, &connreq_ptr->base.ov);

	if (FAILED(hr))
		return H2F(hr);

	return FI_SUCCESS;
}

static int ofi_nd_pep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	if (fid->fclass != FI_CLASS_PEP || bfid->fclass != FI_CLASS_EQ)
		return -FI_EINVAL;

	nd_pep_t *pep_ptr = container_of(fid, struct nd_pep, fid.fid);
	nd_eq_t *eq_ptr = container_of(bfid, struct nd_eq, fid.fid);
	pep_ptr->eq = eq_ptr;
	return FI_SUCCESS;
}

static int ofi_nd_pep_reject(struct fid_pep *ppep, fid_t handle,
			     const void *param, size_t paramlen)
{
	if (ppep->fid.fclass != FI_CLASS_PEP)
		return -FI_EINVAL;

	if (handle->fclass != FI_CLASS_CONNREQ)
		return -FI_EINVAL;

	nd_connreq_t *connreq = container_of(handle, nd_connreq_t, handle);

	connreq->connector->lpVtbl->Reject(connreq->connector, param,
					   (ULONG)paramlen);

	connreq->connector->lpVtbl->Release(connreq->connector);

	free(connreq);

	return FI_SUCCESS;
}

static int ofi_nd_pep_getopt(struct fid *ep, int level, int optname,
			void *optval, size_t *optlen)
{
	if (level != FI_OPT_ENDPOINT || optname != FI_OPT_CM_DATA_SIZE)
		return -FI_ENOPROTOOPT;

	if (*optlen < sizeof(size_t)) {
		*optlen = sizeof(size_t);
		return -FI_ETOOSMALL;
	}

	*((size_t *)optval) = ND_EP_MAX_CM_DATA_SIZE;
	*optlen = sizeof(size_t);

	return FI_SUCCESS;
}

#endif /* _WIN32 */

