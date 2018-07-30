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
	return -FI_ENOSYS;
}

static int ofi_nd_pep_listen(struct fid_pep *ppep)
{
	if (!ppep )
		return -FI_EINVAL;

	if (ppep->fid.fclass != FI_CLASS_PEP)
		return -FI_EINVAL;

	nd_pep_t *pep = container_of(ppep, struct nd_pep, fid);

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


		HRESULT hr = pep->adapter->lpVtbl->CreateOverlappedFile(pep->adapter,
								&pep->adapter_file);
		if (FAILED(hr))
			return H2F(hr);
		if (pep->adapter_file == INVALID_HANDLE_VALUE)
			return -FI_ENODATA;

		/* TODO implement domain_io_cb */
		/* BindIoCompletionCallback(pep->adapter_file, domain_io_cb, 0); */

		hr = pep->adapter->lpVtbl->CreateListener(pep->adapter,
							  &IID_IND2Listener,
							  pep->adapter_file,
							  (void**)&pep->listener);
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
	/* TODO add nd_pep_connreq */
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
	return -FI_ENOSYS;
}

static int ofi_nd_pep_getopt(struct fid *ep, int level, int optname,
			void *optval, size_t *optlen)
{
	return -FI_ENOSYS;
}

#endif /* _WIN32 */

