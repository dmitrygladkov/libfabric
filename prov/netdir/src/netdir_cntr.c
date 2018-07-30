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

#include "netdir.h"

#include "rdma/fabric.h"
#include "ofi_util.h"

static int ofi_nd_cntr_close(struct fid *fid);
static uint64_t ofi_nd_cntr_read(struct fid_cntr *cntr);
static uint64_t ofi_nd_cntr_readerr(struct fid_cntr *cntr);
static int ofi_nd_cntr_add(struct fid_cntr *cntr, uint64_t value);
static int ofi_nd_cntr_set(struct fid_cntr *cntr, uint64_t value);
static int ofi_nd_cntr_wait(struct fid_cntr *cntr,
			    uint64_t threshold, int timeout);

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_cntr_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fid ofi_nd_fid = {
	.fclass = FI_CLASS_CNTR,
	.context = NULL,
	.ops = &ofi_nd_fi_ops
};

static struct fi_ops_cntr ofi_nd_cntr_ops = {
	.size = sizeof(ofi_nd_cntr_ops),
	.read = ofi_nd_cntr_read,
	.readerr = ofi_nd_cntr_readerr,
	.add = ofi_nd_cntr_add,
	.set = ofi_nd_cntr_set,
	.wait = ofi_nd_cntr_wait
};

static int ofi_nd_cntr_close(struct fid *fid)
{
	return -FI_ENOSYS;
}

int ofi_nd_cntr_open(struct fid_domain *pdomain, struct fi_cntr_attr *attr,
		     struct fid_cntr **pcntr, void *context)
{
	return -FI_ENOSYS;
}

static uint64_t ofi_nd_cntr_read(struct fid_cntr *pcntr)
{
	return -FI_ENOSYS;
}

static uint64_t ofi_nd_cntr_readerr(struct fid_cntr *pcntr)
{
	return -FI_ENOSYS;
}

static int ofi_nd_cntr_add(struct fid_cntr *pcntr, uint64_t value)
{
	return -FI_ENOSYS;
}

static int ofi_nd_cntr_set(struct fid_cntr *pcntr, uint64_t value)
{
	return -FI_ENOSYS;
}

static int ofi_nd_cntr_wait(struct fid_cntr *pcntr, 
			    uint64_t threshold, int timeout)
{
	return -FI_ENOSYS;
}

#endif /* _WIN32 */

