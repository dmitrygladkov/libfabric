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
#include "netdir_log.h"

#include "rdma/fabric.h"
#include "rdma/fi_endpoint.h"

#include "ofi.h"
#include "ofi_util.h"

static ssize_t
ofi_nd_ep_read(struct fid_ep *ep, void *buf, size_t len, void *desc,
	       fi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
}

static ssize_t
ofi_nd_ep_readv(struct fid_ep *pep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t src_addr, uint64_t addr, uint64_t key,
		void *context)
{
}

static ssize_t
ofi_nd_ep_readmsg(struct fid_ep *pep, const struct fi_msg_rma *msg,
		  uint64_t flags)
{
}

static ssize_t
ofi_nd_ep_write(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
}

static ssize_t
ofi_nd_ep_writev(struct fid_ep *pep, const struct iovec *iov, void **desc,
		 size_t count, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		 void *context)
{
}

static ssize_t
ofi_nd_ep_writemsg(struct fid_ep *pep, const struct fi_msg_rma *msg,
		   uint64_t flags)
{
}

static ssize_t
ofi_nd_ep_inject(struct fid_ep *pep, const void *buf, size_t len,
		 fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
}

static ssize_t
ofi_nd_ep_writedata(struct fid_ep *pep, const void *buf, size_t len, void *desc,
		    uint64_t data, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		    void *context)
{
}

static ssize_t
ofi_nd_ep_writeinjectdata(struct fid_ep *ep, const void *buf, size_t len,
			  uint64_t data, fi_addr_t dest_addr, uint64_t addr,
			  uint64_t key)
{
}

struct fi_ops_rma ofi_nd_ep_rma = {
	.size = sizeof(ofi_nd_ep_rma),
	.read = ofi_nd_ep_read,
	.readv = ofi_nd_ep_readv,
	.readmsg = ofi_nd_ep_readmsg,
	.write = ofi_nd_ep_write,
	.writev = ofi_nd_ep_writev,
	.writemsg = ofi_nd_ep_writemsg,
	.inject = ofi_nd_ep_inject,
	.writedata = ofi_nd_ep_writedata,
	.injectdata = ofi_nd_ep_writeinjectdata
};

#endif /* _WIN32 */

