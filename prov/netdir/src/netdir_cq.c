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

static int ofi_nd_cq_close(struct fid *fid)
{
}

int ofi_nd_cq_open(struct fid_domain *pdomain, struct fi_cq_attr *attr,
		   struct fid_cq **pcq_fid, void *context)
{
}

static ssize_t ofi_nd_cq_read(struct fid_cq *pcq, void *buf, size_t count)
{
}

static ssize_t ofi_nd_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
				  fi_addr_t *src_addr)
{
}

static ssize_t ofi_nd_cq_readerr(struct fid_cq *pcq, struct fi_cq_err_entry *buf,
				 uint64_t flags)
{
}

static ssize_t ofi_nd_cq_sread(struct fid_cq *pcq, void *buf, size_t count,
			       const void *cond, int timeout)
{
}

static ssize_t ofi_nd_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
				   fi_addr_t *src_addr, const void *cond,
				   int timeout)
{
}

static const char *ofi_nd_cq_strerror(struct fid_cq *cq, int prov_errno,
				      const void *err_data, char *buf,
				      size_t len)
{
}

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_cq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fid ofi_nd_fid = {
	.fclass = FI_CLASS_CQ,
	.context = NULL,
	.ops = &ofi_nd_fi_ops
};

static struct fi_ops_cq ofi_nd_cq_ops = {
	.size = sizeof(ofi_nd_cq_ops),
	.read = ofi_nd_cq_read,
	.readfrom = ofi_nd_cq_readfrom,
	.readerr = ofi_nd_cq_readerr,
	.sread = ofi_nd_cq_sread,
	.sreadfrom = ofi_nd_cq_sreadfrom,
	.signal = fi_no_cq_signal,
	.strerror = ofi_nd_cq_strerror
};

#endif /* _WIN32 */

