/*
 * Copyright (c) 2017 Cray Inc. All rights reserved.
 * Copyright (c) 2017 Intel Inc. All rights reserved.
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
#include <inttypes.h>

#define UTIL_SMRN_GET_PROV(smrn)	((smrn)->attr.prov)

static struct util_smrn global_smrn;

static inline int
util_check_smrn_attr_sanity(struct util_smrn_attr *attr)
{
	/* callbacks and provider must be provided */
	if (!attr || !attr->prov ||
	    !attr->init || !attr->open || !attr->close ||
	    !attr->monitor || !attr->unmonitor || !attr->get_event)
		return -FI_EINVAL;

	/* valid otherwise */
	return FI_SUCCESS;
}

int ofi_util_smrn_init(struct util_smrn_attr *attr)
{
	int ret;

	ret = util_check_smrn_attr_sanity(attr);
	if (ret)
		return ret;

	memcpy(&global_smrn.attr, attr, sizeof(*attr));
	fastlock_init(&global_smrn.lock);
	global_smrn.references = 0;
	dlist_init(&global_smrn.rq_head);

	return global_smrn.attr.init();
}

int ofi_util_smrn_open(struct util_smrn **smrn)
{
	int ret = FI_SUCCESS;

	fastlock_acquire(&global_smrn.lock);
	if (global_smrn.references == 0)
		ret = global_smrn.attr.open(&global_smrn.notifier);

	if (!ret)
		global_smrn.references += 1;
	fastlock_release(&global_smrn.lock);

	if (!ret)
		*smrn = &global_smrn;

	return ret;
}

int ofi_util_smrn_close(struct util_smrn *smrn)
{
	int ret = FI_SUCCESS;

	fastlock_acquire(&smrn->lock);
	if (smrn->references == 0)
		ret = -FI_EINVAL;

	if (smrn->references == 1)
		ret = smrn->attr.close(smrn->notifier);

	if (!ret)
		smrn->references--;
	fastlock_release(&smrn->lock);

	return ret;
}

int ofi_util_smrn_monitor(struct util_smrn *smrn,
			  struct util_smrn_rq *rq,
			  void *addr, uint64_t len,
			  uint64_t cookie,
			  struct util_smrn_context *context)
{
	int ret = FI_SUCCESS;

	if (!context || !rq || !smrn)
		return -FI_EINVAL;

	context->rq = rq;
	context->cookie = cookie;

	ret = smrn->attr.monitor(smrn->notifier, addr,
				 len, (uint64_t)context);
	if (!ret)
		FI_DBG(UTIL_SMRN_GET_PROV(smrn), FI_LOG_FABRIC,
		       "monitoring addr=%p len=%"PRIu64" cookie=%"PRIu64
		       "context=%p rq=%p notifier=%p\n",
		       addr, len, context->cookie,
		       context, rq, smrn->notifier);
	return ret;
}

int ofi_util_smrn_unmonitor(struct util_smrn *smrn,
			    uint64_t cookie,
			    struct util_smrn_context *context)
{
	if (!smrn || (cookie != context->cookie))
		return -FI_EINVAL;

	return smrn->attr.unmonitor(smrn->notifier,
				    (uint64_t)context);
}

static void util_smrn_read_events(struct util_smrn *smrn)
{
	struct util_smrn_context *context = NULL;
	struct util_smrn_rq *rq;
	int ret, len = (int)sizeof(uint64_t);

	do {
		ret = smrn->attr.get_event(smrn->notifier,
					   (void *)&context,
					   len);
		if (ret != len) {
			FI_DBG(UTIL_SMRN_GET_PROV(smrn), FI_LOG_FABRIC,
			       "no more events to be read\n");
			break;
		}

		FI_DBG(UTIL_SMRN_GET_PROV(smrn), FI_LOG_FABRIC,
		       "found event, context=%p rq=%p cookie=%lx\n",
		       context, context->rq, context->cookie);

		rq = context->rq;
		fastlock_acquire(&rq->lock);
		dlist_insert_tail(&context->entry, &rq->list);
		fastlock_release(&rq->lock);
	} while (ret == len);
}

int ofi_util_smrn_get_event(struct util_smrn *smrn,
			    struct util_smrn_rq *rq,
			    struct util_smrn_context **context)
{
	int ret;

	if (!smrn || !context)
		return -FI_EINVAL;

	util_smrn_read_events(smrn);

	fastlock_acquire(&rq->lock);
	if (!dlist_empty(&rq->list)) {
		dlist_pop_front(&rq->list,
				struct util_smrn_context,
				*context, entry);
		ret = FI_SUCCESS;
	} else {
		ret = -FI_EAGAIN;
	}
	fastlock_release(&rq->lock);

	return ret;
}
