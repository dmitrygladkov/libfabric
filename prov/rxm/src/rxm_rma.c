/*
 * Copyright (c) 2017 Intel Corporation. All rights reserved.
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

#include "rxm.h"

typedef ssize_t rxm_rma_msg_fn(struct fid_ep *ep_fid,
			       const struct fi_msg_rma *msg, uint64_t flags);

static inline ssize_t
rxm_ep_rma_reg_iov(struct rxm_ep *rxm_ep, const struct iovec *msg_iov,
		   void **desc, void **desc_storage, size_t iov_count,
		   uint64_t comp_flags, struct rxm_rma_buf *rma_buf)
{
	size_t i;

	if (rxm_ep->msg_mr_local) {
		if (!rxm_ep->rxm_mr_local) {
			ssize_t ret =
				rxm_ep_msg_mr_regv(rxm_ep, msg_iov, iov_count,
						   comp_flags & (FI_WRITE | FI_READ),
						   rma_buf->mr.mr);
			if (OFI_UNLIKELY(ret))
				return ret;

			rma_buf->mr.count = iov_count;
			for (i = 0; i < iov_count; i++)
				desc_storage[i] = fi_mr_desc(rma_buf->mr.mr[i]);
		} else {
			for (i = 0; i < iov_count; i++)
				desc_storage[i] = fi_mr_desc(desc[i]);
		}
	}
	return FI_SUCCESS;
}

static inline ssize_t
rxm_ep_rma_common(struct rxm_ep *rxm_ep, const struct fi_msg_rma *msg, uint64_t flags,
		  rxm_rma_msg_fn rma_msg, uint64_t comp_flags)
{
	struct rxm_rma_buf *rma_buf;
	struct fi_msg_rma msg_rma = *msg;
	struct rxm_conn *rxm_conn;
	void *mr_desc[RXM_IOV_LIMIT] = { 0 };
	int ret;

	assert(msg->rma_iov_count <= rxm_ep->rxm_info->tx_attr->rma_iov_limit);
	assert(((flags & FI_INJECT) &&
	        (ofi_total_iov_len(msg->msg_iov, msg->iov_count) <=
			rxm_ep->msg_info->tx_attr->inject_size)) ||
	       !(flags & FI_INJECT));

	ret = rxm_ep_prepare_tx(rxm_ep, msg->addr, &rxm_conn);
	if (OFI_UNLIKELY(ret))
		return ret;

	rma_buf = rxm_rma_buf_get(rxm_ep);
	if (OFI_UNLIKELY(!rma_buf)) {
		FI_WARN(&rxm_prov, FI_LOG_EP_DATA,
			"Ran out of buffers from RMA buffer pool\n");
		return -FI_ENOMEM;
	}

	rma_buf->app_context = msg->context;
	rma_buf->flags = flags;

	if (!(flags & FI_INJECT)) {
		ret = rxm_ep_rma_reg_iov(rxm_ep, msg_rma.msg_iov, msg_rma.desc, mr_desc,
					 msg_rma.iov_count, comp_flags & (FI_WRITE | FI_READ),
					 rma_buf);
		if (OFI_UNLIKELY(ret))
			goto err;
	}
	msg_rma.desc = mr_desc;
	msg_rma.context = rma_buf;

	ret = rma_msg(rxm_conn->msg_ep, &msg_rma, flags | FI_COMPLETION);
	if (OFI_LIKELY(!ret))
		return ret;

	if (rxm_ep->msg_mr_local && !rxm_ep->rxm_mr_local && !(flags & FI_INJECT))
		rxm_ep_msg_mr_closev(rma_buf->mr.mr, rma_buf->mr.count);
err:
	rxm_rma_buf_release(rxm_ep, rma_buf);
	return ret;
}

static inline ssize_t
rxm_ep_readmsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg, uint64_t flags)
{
	struct rxm_ep *rxm_ep =
		container_of(ep_fid, struct rxm_ep, util_ep.ep_fid.fid);

	return rxm_ep_rma_common(rxm_ep, msg, flags,
				 fi_readmsg, FI_READ);
}

static ssize_t rxm_ep_readv(struct fid_ep *ep_fid, const struct iovec *iov,
			    void **desc, size_t count, fi_addr_t src_addr,
			    uint64_t addr, uint64_t key, void *context)
{
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.len = ofi_total_iov_len(iov, count),
		.key = key,
	};
	struct fi_msg_rma msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.addr = src_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = context,
		.data = 0,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_readmsg(ep_fid, &msg, rxm_ep_tx_flags(rxm_ep));
}

static ssize_t rxm_ep_read(struct fid_ep *ep_fid, void *buf, size_t len,
			   void *desc, fi_addr_t src_addr, uint64_t addr,
			   uint64_t key, void *context)
{
	struct iovec iov = {
		.iov_base = (void*)buf,
		.iov_len = len,
	};
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.len = len,
		.key = key,
	};
	struct fi_msg_rma msg = {
		.msg_iov = &iov,
		.desc = &desc,
		.iov_count = 1,
		.addr = src_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = context,
		.data = 0,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_readmsg(ep_fid, &msg, rxm_ep_tx_flags(rxm_ep));
}

static inline ssize_t
rxm_ep_writemsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg, uint64_t flags)
{
	struct rxm_ep *rxm_ep =
		container_of(ep_fid, struct rxm_ep, util_ep.ep_fid.fid);

	return rxm_ep_rma_common(rxm_ep, msg, flags, fi_writemsg, FI_WRITE);
}

static ssize_t rxm_ep_writev(struct fid_ep *ep_fid, const struct iovec *iov,
			     void **desc, size_t count, fi_addr_t dest_addr,
			     uint64_t addr, uint64_t key, void *context)
{
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.len = ofi_total_iov_len(iov, count),
		.key = key,
	};
	struct fi_msg_rma msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.addr = dest_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = context,
		.data = 0,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_writemsg(ep_fid, &msg, rxm_ep_tx_flags(rxm_ep));
}

static ssize_t rxm_ep_writedata(struct fid_ep *ep_fid, const void *buf,
				size_t len, void *desc, uint64_t data,
				fi_addr_t dest_addr, uint64_t addr,
				uint64_t key, void *context)
{
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.len = len,
		.key = key,
	};
	struct iovec iov = {
		.iov_base = (void*)buf,
		.iov_len = len,
	};
	struct fi_msg_rma msg = {
		.msg_iov = &iov,
		.desc = &desc,
		.iov_count = 1,
		.addr = dest_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = context,
		.data = data,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_writemsg(ep_fid, &msg, rxm_ep_tx_flags(rxm_ep) |
			       FI_REMOTE_CQ_DATA);
}

static ssize_t rxm_ep_write(struct fid_ep *ep_fid, const void *buf,
			    size_t len, void *desc, fi_addr_t dest_addr,
			    uint64_t addr, uint64_t key, void *context)
{
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.len = len,
		.key = key,
	};
	struct iovec iov = {
		.iov_base = (void*)buf,
		.iov_len = len,
	};
	struct fi_msg_rma msg = {
		.msg_iov = &iov,
		.desc = &desc,
		.iov_count = 1,
		.addr = dest_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = context,
		.data = 0,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_writemsg(ep_fid, &msg, rxm_ep_tx_flags(rxm_ep));
}

static ssize_t rxm_ep_inject_write(struct fid_ep *ep_fid, const void *buf,
				   size_t len, fi_addr_t dest_addr,
				   uint64_t addr, uint64_t key)
{
	ssize_t ret;
	struct rxm_conn *rxm_conn;
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	assert(len <= rxm_ep->msg_info->tx_attr->inject_size);

	ret = rxm_ep_prepare_tx(rxm_ep, dest_addr, &rxm_conn);
	if (OFI_UNLIKELY(ret))
		return ret;

	ret = fi_inject_write(rxm_conn->msg_ep, buf, len,
			      dest_addr, addr, key);
	if (OFI_LIKELY(!ret)) {
		ofi_ep_wr_cntr_inc(&rxm_ep->util_ep);
	} else {
		FI_DBG(&rxm_prov, FI_LOG_EP_DATA,
		       "fi_inject_write for MSG provider failed with ret - %"
		       PRId64"\n", ret);
		if (OFI_LIKELY(ret == -FI_EAGAIN))
			rxm_ep_progress_multi(&rxm_ep->util_ep);
	}
	return ret;
}

static ssize_t rxm_ep_inject_writedata(struct fid_ep *ep_fid, const void *buf,
				       size_t len, uint64_t data,
				       fi_addr_t dest_addr, uint64_t addr,
				       uint64_t key)
{
	ssize_t ret;
	struct rxm_conn *rxm_conn;
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);
	ret = rxm_ep_prepare_tx(rxm_ep, dest_addr, &rxm_conn);
	if (OFI_UNLIKELY(ret))
		return ret;

	ret = fi_inject_writedata(rxm_conn->msg_ep, buf, len,
				  data, dest_addr, addr, key);
	if (OFI_LIKELY(!ret)) {
		ofi_ep_wr_cntr_inc(&rxm_ep->util_ep);
	} else {
		FI_DBG(&rxm_prov, FI_LOG_EP_DATA,
		       "fi_inject_writedata for MSG provider failed with ret - %"
		       PRId64"\n", ret);
		if (OFI_LIKELY(ret == -FI_EAGAIN))
			rxm_ep_progress_multi(&rxm_ep->util_ep);
	}
	return ret;
}

struct fi_ops_rma rxm_ops_rma = {
	.size = sizeof (struct fi_ops_rma),
	.read = rxm_ep_read,
	.readv = rxm_ep_readv,
	.readmsg = rxm_ep_readmsg,
	.write = rxm_ep_write,
	.writev = rxm_ep_writev,
	.writemsg = rxm_ep_writemsg,
	.inject = rxm_ep_inject_write,
	.writedata = rxm_ep_writedata,
	.injectdata = rxm_ep_inject_writedata,
};
