/*
 * Copyright (c) 2016-2017 Cray Inc. All rights reserved.
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

#include "ofi_mr.h"

enum util_mr_mgr_entry_state {
	UTIL_MR_MGR_ENTRY_STATE_INIT	= 0,
	UTIL_MR_MGR_ENTRY_STATE_INUSE	= 1,
	UTIL_MR_MGR_ENTRY_STATE_STALE	= 2,
};

struct util_mr_mgr_entry_flags {
	unsigned int is_retired : 1;	/* in use, but not to be reused */
	unsigned int is_merged : 1;	/* merged entry, i.e., not an original
					 * request from fi_mr_reg */
	unsigned int is_unmapped : 1;	/* at least 1 page of the entry has been
					 * unmapped by the OS */
};

struct ofi_mr_region {
	struct iovec			iov;
	struct util_mr_mgr_entry_flags	flags;
	enum util_mr_mgr_entry_state	state;
	ofi_atomic32_t			use_cnt;
	struct dlist_entry		lru_entry;

	ofi_mr_handle_t			handle[1];
};

static inline enum util_mr_mgr_entry_state
util_mr_mgr_entry_get_state(struct ofi_mr_region *entry)
{
	return entry->state;
}

static inline void
util_mr_mgr_entry_set_state(struct ofi_mr_region *entry,
			    enum util_mr_mgr_entry_state state)
{
	entry->state = state;
}

static inline void util_mr_mgr_entry_set_flags(struct ofi_mr_region *entry,
					       struct util_mr_mgr_entry_flags flags)
{
	entry->flags = flags;
}

static inline void util_mr_mgr_entry_reset_flags(struct ofi_mr_region *entry)
{
	entry->flags.is_retired = 0;
	entry->flags.is_merged = 0;
	entry->flags.is_unmapped = 0;
}

static inline int util_mr_mgr_entry_is_retired(struct ofi_mr_region *entry)
{
	return entry->flags.is_retired;
}

static inline int util_mr_mgr_entry_is_merged(struct ofi_mr_region *entry)
{
	return entry->flags.is_merged;
}

static inline int util_mr_mgr_entry_is_unmapped(struct ofi_mr_region *entry)
{
	return entry->flags.is_unmapped;
}

static inline void util_mr_mgr_entry_set_retired(struct ofi_mr_region *entry)
{
	entry->flags.is_retired = 1;
}

static inline void util_mr_mgr_entry_set_merged(struct ofi_mr_region *entry)
{
	entry->flags.is_merged = 1;
}

static inline void util_mr_mgr_entry_set_unmapped(struct ofi_mr_region *entry)
{
	entry->flags.is_unmapped = 1;
}

static int util_mr_mgr_find_overlapping_addr(void *x, void *y)
{
	struct iovec *to_find  = (struct iovec *)x;
	struct iovec *to_compare = (struct iovec *)y;
	uint64_t to_find_end = (uint64_t)(uintptr_t)to_find->iov_base +
				to_find->iov_len - 1;
	uint64_t to_compare_end = (uint64_t)(uintptr_t)to_compare->iov_base +
				to_compare->iov_len - 1;

	/* format: (x_addr,  x_len) - (y_addr,  y_len) truth_value
	 *
	 * case 1: (0x1000, 0x1000) - (0x1400, 0x0800) true
	 * case 2: (0x1000, 0x1000) - (0x0C00, 0x0800) true
	 * case 3: (0x1000, 0x1000) - (0x1C00, 0x0800) true
	 * case 4: (0x1000, 0x1000) - (0x0C00, 0x2000) true
	 * case 5: (0x1000, 0x1000) - (0x0400, 0x0400) false
	 * case 6: (0x1000, 0x1000) - (0x2400, 0x0400) false
	 */
	if (!((to_find_end < (uint64_t)(uintptr_t)to_compare->iov_base) ||
	      (to_compare_end < (uint64_t)(uintptr_t)to_find->iov_base)))
		return 0;

	/* left */
	if ((uint64_t)(uintptr_t)to_find->iov_base <
	    (uint64_t)(uintptr_t)to_compare->iov_base)
		return -1;

	return 1;
}

static inline int util_mr_mgr_cache_key_comp(void *x, void *y)
{
	struct iovec *to_insert  = (struct iovec *)x;
	struct iovec *to_compare = (struct iovec *)y;

	if ((uint64_t)(uintptr_t)to_compare->iov_base ==
	    (uint64_t)(uintptr_t)to_insert->iov_base)
		return 0;

	/* to the left */
	if ((uint64_t)(uintptr_t)to_insert->iov_base <
	    (uint64_t)(uintptr_t)to_compare->iov_base)
		return -1;

	/* to the right */
	return 1;
}

static inline int util_mr_mgr_attr_sanity(struct ofi_mr_mgr_attr *attr)
{
	/* callbacks must be provided */
	if (!attr || !attr->registration_fn ||
	    !attr->deregistration_fn || !attr->compare_fn)
		return -FI_EINVAL;

	/* valid otherwise */
	return FI_SUCCESS;
}

int ofi_mr_mgr_init(struct ofi_mr_mgr *mgr, struct ofi_mr_mgr_attr *attr)
{
	int ret;

	if (util_mr_mgr_attr_sanity(attr))
		return -FI_EINVAL;

	memcpy(&mgr->attr, attr, sizeof(*attr));
	dlist_init(&mgr->lru_list);

	mgr->mr_inuse_tree = rbtNew(attr->compare_fn);
	if (!mgr->mr_inuse_tree) {
		ret = -FI_ENOMEM;
		goto fn1;
	}

	if (mgr->attr.lazy_deregistration) {
		mgr->mr_stale_tree = rbtNew(attr->compare_fn);
		if (!mgr->mr_stale_tree) {
			ret = -FI_ENOMEM;
			goto fn2;
		}
	}

	return FI_SUCCESS;
fn2:
	rbtDelete(mgr->mr_inuse_tree);
	mgr->mr_inuse_tree = NULL;
fn1:
	return ret;
}

static inline void util_mr_mgr_lru_enqueue(struct ofi_mr_mgr *mgr,
					   struct ofi_mr_region *entry)
{
	dlist_insert_tail(&entry->lru_entry, &mgr->lru_list);
}

static inline int util_mr_mgr_lru_dequeue(struct ofi_mr_mgr *mgr,
					  struct ofi_mr_region **entry)
{
	if (OFI_UNLIKELY(dlist_empty(&mgr->lru_list))) {
		*entry = NULL;
		return -FI_ENOENT;
	}

	/* Takes the first entry from the LRU */
	dlist_pop_front(&mgr->lru_list, struct ofi_mr_region,
			*entry, lru_entry);
	return FI_SUCCESS;
}

static inline void util_mr_mgr_lru_remove(struct ofi_mr_mgr *mgr,
					  struct ofi_mr_region *entry)
{
	dlist_remove(&entry->lru_entry);
}

static inline void util_mr_mgr_entry_destroy(struct ofi_mr_mgr *mgr,
					     struct ofi_mr_region *entry)
{
	mgr->attr.deregistration_fn(mgr, entry->handle);
	
	    /*if (!util_mr_mgr_entry_is_mapped(entry))
		    util_mr_cache_notifier_unmonitor(cache, entry);*/

		util_mr_mgr_entry_reset_flags(entry);
		free(entry);

	return;
}


static inline
void util_mr_mgr_insert_entry_into_stale(struct ofi_mr_mgr *mgr,
					 struct ofi_mr_region *entry)
{
	RbtStatus rc;

	if (util_mr_mgr_entry_is_unmapped(entry)) {
		FI_DBG(/*UTIL_MR_CACHE_GET_PROV(cache)*/&core_prov, FI_LOG_MR,
		       "entry (%p) unmapped, not inserting into stale %p:%"PRIu64"\n",
		       entry, entry->iov.iov_base, entry->iov.iov_len);
		/* Should we return some other value? */
		return;
	}

	rc = rbtInsert(mgr->mr_stale_tree, &entry->iov, entry);
	if (rc != RBT_STATUS_OK) {
		FI_WARN(/*UTIL_MR_CACHE_GET_PROV(cache)*/&core_prov, FI_LOG_MR,
			"could not insert into stale rb tree,"
			" rc=%d key.addr=%p length=%"PRIu64" entry=%p\n",
			rc, entry->iov.iov_base, entry->iov.iov_len, entry);

		util_mr_mgr_entry_destroy(mgr, entry);
	} else {
		FI_DBG(/*UTIL_MR_CACHE_GET_PROV(cache)*/&core_prov, FI_LOG_MR,
		       "inserted key=%p:%"PRIu64" into stale\n",
		       entry->iov.iov_base, entry->iov.iov_len);

		util_mr_mgr_lru_enqueue(mgr, entry);
		switch (util_mr_mgr_entry_get_state(entry)) {
		case UTIL_MR_MGR_ENTRY_STATE_INUSE:
			util_mr_mgr_entry_set_state(entry,
						    UTIL_MR_MGR_ENTRY_STATE_STALE);
			break;
		default:
			FI_WARN(/*UTIL_MR_CACHE_GET_PROV(cache)*/&core_prov, FI_LOG_MR,
				"stale entry (%p) %p:%"PRIu64" in bad state (%d)\n",
				entry, entry->iov.iov_base,
				entry->iov.iov_len, (int)entry->state);
		}
	}

	return;
}

static int util_mr_mgr_flush(struct ofi_mr_mgr *mgr, size_t flush_count)
{
	int ret;
	size_t destroyed = 0;
	RbtIterator iter;
	struct ofi_mr_region *entry;

	/* flushes are unnecessary for MR mgr w/o lazy deregistration */
	if (!mgr->attr.lazy_deregistration)
		return FI_SUCCESS;

	while (!dlist_empty(&mgr->lru_list)) {
		if (flush_count == destroyed)
			break;
		ret = util_mr_mgr_lru_dequeue(mgr, &entry);
		if (OFI_UNLIKELY(ret)) {
			break;
		}

		iter = rbtFind(mgr->mr_stale_tree, &entry->iov);
		if (OFI_UNLIKELY(!iter)) {
			break;
		}

		ret = rbtErase(mgr->mr_stale_tree, iter);
		if (OFI_UNLIKELY(ret != RBT_STATUS_OK)) {
			break;
		}

		util_mr_mgr_entry_destroy(mgr, entry);
		++destroyed;
	}

	return FI_SUCCESS;
}

void ofi_mgr_mgr_cleanup(struct ofi_mr_mgr *mgr)
{
	rbtDelete(mgr->mr_inuse_tree);
	mgr->mr_inuse_tree = NULL;

	if (mgr->attr.lazy_deregistration) {
		rbtDelete(mgr->mr_stale_tree);
		mgr->mr_stale_tree = NULL;
	}
}
