/*
 * Copyright (c) 2017 Intel Corporation, Inc.  All rights reserved.
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

#include <fi_util.h>
#include "fi_verbs.h"

static int fi_ibv_mr_close(fid_t fid)
{
	struct fi_ibv_mem_desc *md =
		container_of(fid, struct fi_ibv_mem_desc, mr_fid.fid);
	int ret;

	ret = md->domain->mr_cache_ops->dereg_mr(md->domain, md);
	if (ret)
		return ret;

	return ret;
}

static struct fi_ops fi_ibv_mr_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_ibv_mr_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static void *fi_ibv_register_region(void *handle, void *address, size_t length,
				    struct util_fi_reg_context *fi_reg_context,
				    void *context)
{
	int fi_ibv_access = 0;
	uint64_t access = fi_reg_context->access;
	struct fi_ibv_mem_desc *md = handle;

	md->domain = (struct fi_ibv_domain *)context;
	md->mr_fid.fid.fclass = FI_CLASS_MR;
	md->mr_fid.fid.context = context;
	md->mr_fid.fid.ops = &fi_ibv_mr_ops;

	/* Enable local write access by default for FI_EP_RDM which hides local
	 * registration requirements. This allows to avoid buffering or double
	 * registration */
	if (!(md->domain->info->caps & FI_LOCAL_MR) ||
	    (md->domain->info->domain_attr->mr_mode & FI_MR_LOCAL))
		fi_ibv_access |= IBV_ACCESS_LOCAL_WRITE;

	/* Local read access to an MR is enabled by default in verbs */
	if (access & FI_RECV)
		fi_ibv_access |= IBV_ACCESS_LOCAL_WRITE;

	/* iWARP spec requires Remote Write access for an MR that is used
	 * as a data sink for a Remote Read */
	if (access & FI_READ) {
		fi_ibv_access |= IBV_ACCESS_LOCAL_WRITE;
		if (md->domain->verbs->device->transport_type == IBV_TRANSPORT_IWARP)
			fi_ibv_access |= IBV_ACCESS_REMOTE_WRITE;
	}

	if (access & FI_WRITE)
		fi_ibv_access |= IBV_ACCESS_LOCAL_WRITE;

	if (access & FI_REMOTE_READ)
		fi_ibv_access |= IBV_ACCESS_REMOTE_READ;

	/* Verbs requires Local Write access too for Remote Write access */
	if (access & FI_REMOTE_WRITE)
		fi_ibv_access |= IBV_ACCESS_LOCAL_WRITE |
				 IBV_ACCESS_REMOTE_WRITE |
				 IBV_ACCESS_REMOTE_ATOMIC;

	fi_ibv_access |= IBV_ACCESS_LOCAL_WRITE |
				 IBV_ACCESS_REMOTE_WRITE |
				 IBV_ACCESS_REMOTE_ATOMIC |
				 IBV_ACCESS_REMOTE_READ;

	md->mr = ibv_reg_mr(md->domain->pd, (void *)address,
			    length, fi_ibv_access);
	if (!md->mr)
		goto err;

	md->mr_fid.mem_desc = (void *)(uintptr_t)md->mr->lkey;
	md->mr_fid.key = md->mr->rkey;

	return md;
err:
	free(md);
	return NULL;
}

static int fi_ibv_deregister_region(void *handle, void *context)
{
	/* do NOT free fi_ibv_mem_desc here.
	 * The fi_ibv_mem_desc is freed when MR cache entry is freed */
	return -ibv_dereg_mr(((struct fi_ibv_mem_desc *)handle)->mr);
}

static int
fi_ibv_mr_reg(struct fid *fid, const void *buf, size_t len,
	      uint64_t access, uint64_t offset, uint64_t requested_key,
	      uint64_t flags, struct fid_mr **mr, void *context)
{
	struct fi_ibv_mem_desc *md;
	int ret;
	struct util_fi_reg_context fi_reg_context = {
		.access		= access,
		.offset		= offset,
		.requested_key	= requested_key,
		.flags		= flags,
		.context	= context,
	};
	struct fid_domain *domain_fid = container_of(fid, struct fid_domain,
						     fid);
	struct fi_ibv_domain *domain = container_of(domain_fid, struct fi_ibv_domain,
						    util_domain.domain_fid);

	/* Flags are reserved for future use and must be 0. */
	if (OFI_UNLIKELY(flags))
		return -FI_EBADFLAGS;

	ret = domain->mr_cache_ops->reg_mr(domain_fid,
					   (uint64_t)(uintptr_t)buf, len,
					   &fi_reg_context,
					   (void **)&md);
	if (ret)
		return ret;

	*mr = &md->mr_fid;
	if (md->domain->eq_flags & FI_REG_MR) {
		struct fi_eq_entry entry = {
			.fid = &md->mr_fid.fid,
			.context = context,
		};
		if (md->domain->eq)
			fi_ibv_eq_write_event(md->domain->eq, FI_MR_COMPLETE,
					      &entry, sizeof(entry));
		else if (md->domain->util_domain.eq)
			/* This branch is taken for the verbs/DGRAM */
			fi_eq_write(&md->domain->util_domain.eq->eq_fid,
				    FI_MR_COMPLETE, &entry, sizeof(entry), 0);
	}
	return FI_SUCCESS;
}

static int fi_ibv_mr_regv(struct fid *fid, const struct iovec * iov,
			  size_t count, uint64_t access, uint64_t offset,
			  uint64_t requested_key, uint64_t flags,
			  struct fid_mr **mr, void *context)
{
	if (count > VERBS_MR_IOV_LIMIT) {
		VERBS_WARN(FI_LOG_FABRIC,
			   "iov count > %d not supported\n",
			   VERBS_MR_IOV_LIMIT);
		return -FI_EINVAL;
	}
	return fi_ibv_mr_reg(fid, iov->iov_base, iov->iov_len,
			     access, offset, requested_key,
			     flags, mr, context);
}

static int fi_ibv_mr_regattr(struct fid *fid, const struct fi_mr_attr *attr,
			     uint64_t flags, struct fid_mr **mr)
{
	return fi_ibv_mr_regv(fid, attr->mr_iov, attr->iov_count,
			      attr->access, 0, attr->requested_key,
			      flags, mr, attr->context);
}

struct fi_ops_mr fi_ibv_domain_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = fi_ibv_mr_reg,
	.regv = fi_ibv_mr_regv,
	.regattr = fi_ibv_mr_regattr,
};

static int fi_ibv_mr_cache_init(struct fid_domain *domain_fid)
{
	struct fi_ibv_domain *domain =
		container_of(domain_fid, struct fi_ibv_domain,
			     util_domain.domain_fid);
	int ret;

	ret = ofi_util_mr_cache_init(&domain->mr_cache,
				     &domain->mr_cache_attr);
	if (!ret)
		domain->mr_cache_inuse = 1;

	return ret;
}

static int fi_ibv_mr_cache_is_init(struct fid_domain *domain_fid)
{
	struct fi_ibv_domain *domain =
		container_of(domain_fid, struct fi_ibv_domain,
			     util_domain.domain_fid);

	return domain->mr_cache_inuse;
}

static int fi_ibv_mr_cache_reg_mr(struct fid_domain *domain_fid,
				  uint64_t address, uint64_t length,
				  struct util_fi_reg_context *fi_reg_context,
				  void **handle)
{
	struct fi_ibv_domain *domain =
		container_of(domain_fid, struct fi_ibv_domain,
			     util_domain.domain_fid);

	return ofi_util_mr_cache_register(domain->mr_cache, address, length,
					  fi_reg_context, handle);
}

static int fi_ibv_mr_cache_dereg_mr(struct fi_ibv_domain *domain,
				    struct fi_ibv_mem_desc *md)
{
	return ofi_util_mr_cache_deregister(domain->mr_cache, md);
}

static int fi_ibv_mr_cache_close(struct fid_domain *domain_fid)
{
	struct fi_ibv_domain *domain =
		container_of(domain_fid, struct fi_ibv_domain,
			     util_domain.domain_fid);
	int ret;

	if (!domain->mr_cache_inuse)
		return FI_SUCCESS;

	ret = ofi_util_mr_cache_destroy(domain->mr_cache);
	if (ret)
		VERBS_WARN(FI_LOG_DOMAIN,
			   "Unable to destroy MR Cache ret = %d", ret);

	domain->mr_cache = NULL;
	domain->mr_cache_inuse = 0;

	return FI_SUCCESS;
}

static int fi_ibv_mr_cache_flush(struct fid_domain *domain_fid)
{
	struct fi_ibv_domain *domain =
		container_of(domain_fid, struct fi_ibv_domain,
			     util_domain.domain_fid);
	return ofi_util_mr_cache_flush(domain->mr_cache);
}

struct fi_ibv_mr_cache_ops fi_ibv_mr_cache_ops = {
	.init = fi_ibv_mr_cache_init,
	.is_init = fi_ibv_mr_cache_is_init,
	.reg_mr = fi_ibv_mr_cache_reg_mr,
	.dereg_mr = fi_ibv_mr_cache_dereg_mr,
	.destroy_cache = fi_ibv_mr_cache_close,
	.flush_cache = fi_ibv_mr_cache_flush,
};

int fi_ibv_open_mr_cache(struct fid_domain *domain_fid)
{
	struct fi_ibv_domain *domain =
		container_of(domain_fid, struct fi_ibv_domain,
			     util_domain.domain_fid);

	if (domain->mr_cache_ops && domain->mr_cache_ops->is_init(domain_fid))
		return -FI_EBUSY;

	return domain->mr_cache_ops->init(domain_fid);
}

struct util_mr_cache_attr fi_ibv_mr_cache_attr_def = {
	.soft_reg_limit		= 4096,
	.hard_reg_limit		= -1,
	.hard_stale_limit	= 128,
	.lazy_deregistration	= 1,
	.reg_callback		= fi_ibv_register_region,
	.dereg_callback		= fi_ibv_deregister_region,
	.elem_size		= sizeof(struct fi_ibv_mem_desc),
};
