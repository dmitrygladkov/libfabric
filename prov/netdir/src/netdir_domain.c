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

#include "ofi.h"
#include "ofi_util.h"
#include "ofi_enosys.h"
#include "rdma/fabric.h"
#include "rdma/fi_domain.h"

static int ofi_nd_domain_close(fid_t fid)
{
	return 0;
}

int ofi_nd_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		       struct fid_domain **pdomain, void *context)
{
	return 0;
}

static int ofi_nd_domain_bind(struct fid *fid, struct fid *bfid,
			      uint64_t flags)
{
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

