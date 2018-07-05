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

int ofi_nd_passive_endpoint(struct fid_fabric *fabric, struct fi_info *info,
			    struct fid_pep **ppep, void *context)
{
	return 0;
}

static int ofi_nd_pep_getname(fid_t fid, void *addr, size_t *addrlen)
{
	return 0;
}

static int ofi_nd_pep_close(struct fid *fid)
{
	return FI_SUCCESS;
}

static int ofi_nd_pep_listen(struct fid_pep *ppep)
{
	return 0;
}

static int ofi_nd_pep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{

	return FI_SUCCESS;
}

static int ofi_nd_pep_reject(struct fid_pep *ppep, fid_t handle,
			     const void *param, size_t paramlen)
{

	return FI_SUCCESS;
}

static int ofi_nd_pep_getopt(struct fid *ep, int level, int optname,
			void *optval, size_t *optlen)
{

	return 0;
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

