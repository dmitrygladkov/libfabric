#ifndef _FI_EXT_VERBS_H_
#define _FI_EXT_VERBS_H_

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "ofi.h"

#define FI_VERBS_EP_OPS_1 "fi_verbs_ep_ops_1"

enum fi_verbs_ep_ops_val {
	FI_VERBS_EP_OPS_SRQ_RECV_WR_SIZE = 0,
};

typedef int (*fi_verbs_get_val)(struct fid_ep *ep_fid, enum fi_verbs_ep_ops_val, void *val);
typedef void (*fi_verbs_alloc_native_srq_recv)(void *wr, void *new_wr, void *new_sge,
					       void *buf, size_t len, void *desc,
					       void *context, uint64_t flags);
typedef ssize_t (*fi_verbs_native_post_srq_recv)(struct fid_ep *ep_fid, void *wr, uint64_t flags);

struct fi_verbs_ops_ep {
	fi_verbs_get_val get_val;
	fi_verbs_alloc_native_srq_recv alloc_native_srq_recv;
	fi_verbs_native_post_srq_recv native_post_srq_recv;
};

#ifdef __cplusplus
}
#endif

#endif /* _FI_EXT_VERBS_H_ */
