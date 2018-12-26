/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

#include "mlx.h"

int mlx_errcode_translation_table[(-UCS_ERR_LAST) + 2] = { -FI_EOTHER };

struct mlx_global_descriptor mlx_descriptor = {
	.use_ns = 0,
	.ns_port = MLX_DEFAULT_NS_PORT,
	.localhost = NULL,
};

static void mlx_init_errcodes(void)
{
	MLX_UCS_2_OFI(UCS_OK)				= FI_SUCCESS;
	MLX_UCS_2_OFI(UCS_INPROGRESS)			= -FI_EAGAIN;
	MLX_UCS_2_OFI(UCS_ERR_NO_MESSAGE)		= -FI_ENOMSG;
	MLX_UCS_2_OFI(UCS_ERR_NO_RESOURCE)		= -FI_EINVAL;
	MLX_UCS_2_OFI(UCS_ERR_IO_ERROR)			= -FI_EIO;
	MLX_UCS_2_OFI(UCS_ERR_NO_MEMORY)		= -FI_ENOMEM;
	MLX_UCS_2_OFI(UCS_ERR_INVALID_PARAM)		= -FI_EINVAL;
	MLX_UCS_2_OFI(UCS_ERR_UNREACHABLE)		= -FI_ENETUNREACH;
	MLX_UCS_2_OFI(UCS_ERR_INVALID_ADDR)		= -FI_EINVAL;
	MLX_UCS_2_OFI(UCS_ERR_NOT_IMPLEMENTED)		= -FI_ENOSYS;
	MLX_UCS_2_OFI(UCS_ERR_MESSAGE_TRUNCATED)	= -FI_EMSGSIZE;
	MLX_UCS_2_OFI(UCS_ERR_NO_PROGRESS)		= -FI_EAGAIN;
	MLX_UCS_2_OFI(UCS_ERR_BUFFER_TOO_SMALL)		= -FI_ETOOSMALL;
	MLX_UCS_2_OFI(UCS_ERR_NO_ELEM)			= -FI_ENOENT;
	MLX_UCS_2_OFI(UCS_ERR_SOME_CONNECTS_FAILED)	= -FI_EIO;
	MLX_UCS_2_OFI(UCS_ERR_NO_DEVICE)		= -FI_ENODEV;
	MLX_UCS_2_OFI(UCS_ERR_BUSY)			= -FI_EBUSY;
	MLX_UCS_2_OFI(UCS_ERR_CANCELED)			= -FI_ECANCELED;
	MLX_UCS_2_OFI(UCS_ERR_SHMEM_SEGMENT)		= -FI_EOTHER;
	MLX_UCS_2_OFI(UCS_ERR_ALREADY_EXISTS)		= -FI_EOTHER;
	MLX_UCS_2_OFI(UCS_ERR_OUT_OF_RANGE)		= -FI_EINVAL;
	MLX_UCS_2_OFI(UCS_ERR_TIMED_OUT)		= -FI_ETIMEDOUT;
	MLX_UCS_2_OFI(UCS_ERR_EXCEEDS_LIMIT)		= -FI_E2BIG;
	MLX_UCS_2_OFI(UCS_ERR_UNSUPPORTED)		= -FI_ENOSYS;
	/*MLX_UCS_2_OFI(UCS_ERR_REJECTED)			= -FI_EOTHER;
	MLX_UCS_2_OFI(UCS_ERR_FIRST_LINK_FAILURE)	= -FI_EOTHER;
	MLX_UCS_2_OFI(UCS_ERR_LAST_LINK_FAILURE)	= -FI_EOTHER;
	MLX_UCS_2_OFI(UCS_ERR_FIRST_ENDPOINT_FAILURE)	= -FI_EOTHER;
	MLX_UCS_2_OFI(UCS_ERR_LAST_ENDPOINT_FAILURE)	= -FI_EOTHER;
	MLX_UCS_2_OFI(UCS_ERR_ENDPOINT_TIMEOUT)		= -FI_ETIMEDOUT;*/
}

static int mlx_getinfo(uint32_t version, const char *node,
		       const char *service, uint64_t flags,
		       const struct fi_info *hints, struct fi_info **info)
{
	return util_getinfo(&mlx_util_prov, version, service, node,
			    flags, hints, info);
}

static void mlx_fini(void)
{
	/* yawn */
}

struct fi_provider mlx_prov = {
	.name = "mlx",
	.version = MLX_VERSION,
	.fi_version = FI_VERSION(1, 7),
	.getinfo = mlx_getinfo,
	.fabric = mlx_fabric_open,
	.cleanup = mlx_fini,
};

struct util_prov mlx_util_prov = {
	.prov = &mlx_prov,
	.info = NULL,
	.flags = 0,
};

const struct fi_fabric_attr mlx_fabric_attr = {
	.prov_version		= FI_VERSION(1,0),
};

const struct fi_domain_attr mlx_domain_attr = {
	.caps			= (FI_LOCAL_COMM | FI_REMOTE_COMM),
	.threading		= FI_THREAD_SAFE,
	.control_progress	= FI_PROGRESS_AUTO,
	.data_progress		= FI_PROGRESS_AUTO,
	.resource_mgmt		= FI_RM_ENABLED,
	.mr_mode		= OFI_MR_BASIC_MAP | FI_MR_LOCAL | FI_MR_BASIC,
	.cq_data_size		= 0,
	.tx_ctx_cnt		= 1024,
	.rx_ctx_cnt		= 1024,
	.max_ep_tx_ctx		= 1,
	.max_ep_rx_ctx		= 1,
	.mr_iov_limit		= 1,
	.max_err_data		= 0, /* ? */
};

const struct fi_ep_attr mlx_ep_attr = {
	.type			= FI_EP_MSG,
	.protocol		= FI_PROTO_UNSPEC,
	.protocol_version	= 1,
	.msg_prefix_size	= 0,
	.max_order_war_size	= 0,
	.mem_tag_format		= 0,
	.tx_ctx_cnt		= 1,
	.rx_ctx_cnt		= 1,
};

const struct fi_tx_attr mlx_tx_attr = {
	.caps			= (MLX_CAPS & (~FI_RECV)),
	.mode			= 0,
	.op_flags		= (FI_INJECT | FI_COMPLETION | FI_TRANSMIT_COMPLETE),
	.msg_order		= MLX_MSG_ORDER,
	.comp_order		= FI_ORDER_STRICT,
	.inject_size		= 0,
	.rma_iov_limit		= 1,
};

const struct fi_rx_attr mlx_rx_attr = {
	.caps			= (MLX_CAPS & (~FI_SEND)),
	.mode			= 0,
	.msg_order		= MLX_MSG_ORDER,
	.comp_order		= FI_ORDER_STRICT | FI_ORDER_DATA,
	.total_buffered_recv	= 0,
};

static struct fi_info *mlx_alloc_fi_info(uct_worker_h worker, uct_md_h md,
					 char *dev_name, char *tl_name)
{
	int ret;
	struct fi_info *fi = NULL;
	uct_iface_config_t *config;
	uct_iface_params_t params = {
		.open_mode = UCT_IFACE_OPEN_MODE_DEVICE,
		.mode.device.tl_name = tl_name,
		.mode.device.dev_name = dev_name,
		.stats_root = NULL,
		.rx_headroom = 0,
        };
	uct_iface_h iface;
	uct_iface_attr_t attr;
	uct_md_attr_t md_attr;

	UCS_CPU_ZERO(&params.cpu_mask);

	/* Read transport-specific interface configuration */
	ret = MLX_UCS_2_OFI(uct_md_iface_config_read(
				md, tl_name, NULL, NULL, &config));
	if (ret) {
		return NULL;
	}

	/* Open communication interface */
	ret = uct_iface_open(md, worker, &params, config, &iface);
	if (ret) {
		return NULL;
	}

	/* Get interface attributes */
	ret = MLX_UCS_2_OFI(uct_iface_query(iface, &attr));
	if (ret) {
		goto close_iface;
	}

	ret = MLX_UCS_2_OFI(uct_md_query(md, &md_attr));
	if (ret) {
		goto close_iface;
	}

	if (!(fi = fi_allocinfo())) {
		ret = -FI_ENOMEM;
		goto close_iface;
	}

	fi->caps = MLX_CAPS;
	fi->mode = 0;
	fi->handle = NULL;
	*(fi->fabric_attr) = mlx_fabric_attr;
	fi->fabric_attr->name = strdup(md_attr.component_name);
	if (!fi->fabric_attr->name) {
		goto free_fi;
	}

	*(fi->domain_attr) = mlx_domain_attr;
	fi->domain_attr->name = strdup(dev_name);
	if (!fi->domain_attr->name) {
		goto free_fabric_name;
	}
	fi->domain_attr->mr_key_size = md_attr.rkey_packed_size;

	*(fi->ep_attr) = mlx_ep_attr;
	fi->ep_attr->max_msg_size = MIN(attr.cap.tag.eager.max_bcopy,
					MIN(attr.cap.put.max_zcopy,
					    attr.cap.get.max_zcopy));

	*(fi->tx_attr) = mlx_tx_attr;
	fi->tx_attr->inject_size = attr.cap.tag.eager.max_bcopy;
	fi->tx_attr->iov_limit = attr.cap.tag.eager.max_iov;
	fi->tx_attr->size = 128;

	*(fi->rx_attr) = mlx_rx_attr;
	fi->rx_attr->iov_limit = attr.cap.tag.recv.max_iov;
	fi->rx_attr->size = 128;

close_iface:
	uct_iface_close(iface);
	return fi;
free_fabric_name:
	free(fi->fabric_attr->name);
	fi->fabric_attr->name = NULL;
free_fi:
	fi_freeinfo(fi);
	fi = NULL;
	goto close_iface;
}

static int mlx_init_fi_info_list(const struct fi_info **info)
{
	int ret;
	unsigned i, j, num_md_resources, num_tl_resources;
	uct_md_resource_desc_t *md_resources;
	uct_tl_resource_desc_t *tl_resources;
	uct_md_config_t *md_config;
	uct_md_h md;
	ucs_async_context_t *async;
	uct_worker_h worker;
	struct fi_info *fi = NULL, *tail = NULL;

	*info = NULL;

	ret = MLX_UCS_2_OFI(ucs_async_context_create(
				UCS_ASYNC_MODE_THREAD, &async));
	if (ret) {
		goto out;
	}

	ret = uct_worker_create(async, UCS_THREAD_MODE_SINGLE, &worker);
	if (ret) {
		goto cleanup_async;
	}

	ret = MLX_UCS_2_OFI(uct_query_md_resources(
				&md_resources, &num_md_resources));
	if (ret) {
		goto destroy_worker;
	}

	/* Iterate through memory domain resources */
	for (i = 0; i < num_md_resources; i++) {
		ret = MLX_UCS_2_OFI(uct_md_config_read(
					md_resources[i].md_name, NULL,
					NULL, &md_config));
		if (ret) {
			goto release_md_res;
		}

		ret = MLX_UCS_2_OFI(uct_md_open(
					md_resources[i].md_name,
					md_config, &md));
		if (ret) {
			goto release_md_res;
		}

		ret = MLX_UCS_2_OFI(uct_md_query_tl_resources(
					md, &tl_resources, &num_tl_resources));
		if (ret) {
			goto close_md;
		}

		/* Go through each available transport */
		for (j = 0; j < num_tl_resources; j++) {
			fi = mlx_alloc_fi_info(worker, md,
					       tl_resources[j].dev_name,
					       tl_resources[j].tl_name);
			if (!fi)
				continue;

			if (!*info)
				*info = fi;
			else
				tail->next = fi;
			tail = fi;
		}

		uct_release_tl_resource_list(tl_resources);
		uct_md_close(md);
	}

release_md_res:
	uct_release_md_resource_list(md_resources);
destroy_worker:
	uct_worker_destroy(worker);
cleanup_async:
	ucs_async_context_destroy(async);
out:
	return ret;
close_md:
	uct_md_close(md);
	goto release_md_res;
}

MLX_INI
{
	mlx_init_errcodes();

	if (mlx_init_fi_info_list(&mlx_util_prov.info)) {
		return NULL;
	}

	fi_param_define(&mlx_prov, "config", FI_PARAM_STRING,
			"MLX configuration file name");

	fi_param_define(&mlx_prov, "ns_port", FI_PARAM_INT,
			"MLX Name server port");

	fi_param_define(&mlx_prov, "ns_enable",FI_PARAM_BOOL,
			"Enforce usage of name server for MLX provider");

	fi_param_define(&mlx_prov, "ns_iface",FI_PARAM_STRING,
			"Specify IPv4 network interface for MLX provider's name server");

	return &mlx_prov;
}
