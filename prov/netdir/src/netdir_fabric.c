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

#include <stdlib.h>
#include <malloc.h>

#include "netdir.h"
#include "ofi_util.h"
#include "ofi_enosys.h"
#include "rdma/fabric.h"

static int ofi_nd_fabric_close(fid_t fid);

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_fabric_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fid ofi_nd_fid = {
	.fclass = FI_CLASS_FABRIC,
	.context = NULL,
	.ops = &ofi_nd_fi_ops
};

static struct fi_ops_fabric ofi_nd_fabric_ops = {
	.size = sizeof(ofi_nd_fabric_ops),
	.domain = ofi_nd_domain_open,
	.passive_ep = ofi_nd_passive_endpoint,
	.eq_open = ofi_nd_eq_open,
	.wait_open = fi_no_wait_open,
	.trywait = fi_no_trywait
};

static int ofi_nd_fabric_close(fid_t fid)
{
	return FI_SUCCESS;
}

int ofi_nd_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fab,
		  void *context)
{

	return FI_SUCCESS;
}

#endif /* _WIN32 */

