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

#include "rdma/fabric.h"
#include "rdma/fi_endpoint.h"

#include "ofi.h"
#include "ofi_util.h"

int ofi_nd_endpoint(struct fid_domain *pdomain, struct fi_info *info,
	struct fid_ep **ep_fid, void *context)
{
}

static int ofi_nd_ep_control(struct fid *fid, int command, void *arg)
{
}

static int ofi_nd_ep_close(struct fid *fid)
{
}

static int ofi_nd_ep_connect(struct fid_ep *pep, const void *addr,
			     const void *param, size_t paramlen)
{
}

static int ofi_nd_ep_accept(struct fid_ep *pep, const void *param, size_t paramlen)
{
}

static int ofi_nd_ep_getname(fid_t fid, void *addr, size_t *addrlen)
{
}

static int ofi_nd_ep_bind(fid_t pep, fid_t bfid, uint64_t flags)
{
}

static int ofi_nd_ep_shutdown(struct fid_ep *pep, uint64_t flags)
{
}

static ssize_t ofi_nd_ep_cancel(fid_t fid, void *context)
{
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

#endif /* _WIN32 */

