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

static ssize_t
ofi_nd_ep_sendmsg(struct fid_ep *pep, const struct fi_msg *msg, uint64_t flags)
{
}

static ssize_t ofi_nd_ep_inject(struct fid_ep *pep, const void *buf, size_t len,
	fi_addr_t dest_addr)
{
}

ssize_t
ofi_nd_ep_injectdata(struct fid_ep *pep, const void *buf, size_t len,
		     uint64_t data, fi_addr_t dest_addr)
{
}

static ssize_t ofi_nd_ep_senddata(struct fid_ep *pep, const void *buf, size_t len, void *desc,
				  uint64_t data, fi_addr_t dest_addr, void *context)
{
}

static ssize_t ofi_nd_ep_send(struct fid_ep *pep, const void *buf, size_t len,
			      void *desc, fi_addr_t dest_addr, void *context)
{
	return ofi_nd_ep_senddata(pep, buf, len, desc, 0, dest_addr, context);
}

static ssize_t ofi_nd_ep_sendv(struct fid_ep *pep, const struct iovec *iov,
			       void **desc, size_t count, fi_addr_t dest_addr,
			       void *context)
{
}

static ssize_t ofi_nd_ep_recvmsg(struct fid_ep *pep, const struct fi_msg *msg,
				 uint64_t flags)
{
}

static ssize_t ofi_nd_ep_recvv(struct fid_ep *pep, const struct iovec *iov,
			       void **desc,
			       size_t count, fi_addr_t src_addr, void *context)
{
}

static ssize_t ofi_nd_ep_recv(struct fid_ep *pep, void *buf, size_t len,
			      void *desc, fi_addr_t src_addr, void *context)
{
}

struct fi_ops_msg ofi_nd_ep_msg = {
	.size = sizeof(ofi_nd_ep_msg),
	.recv = ofi_nd_ep_recv,
	.recvv = ofi_nd_ep_recvv,
	.recvmsg = ofi_nd_ep_recvmsg,
	.send = ofi_nd_ep_send,
	.sendv = ofi_nd_ep_sendv,
	.sendmsg = ofi_nd_ep_sendmsg,
	.inject = ofi_nd_ep_inject,
	.senddata = ofi_nd_ep_senddata,
	.injectdata = ofi_nd_ep_injectdata
};

#endif /* _WIN32 */

