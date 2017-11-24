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

#define IOV_BASE_2_KEY_ADDR(iov)		\
	(uint64_t)(uintptr_t)(iov)->iov_base

#define KEY_ADDR_2_IOV_BASE(tree_key)		\
	(void *)(uintptr_t)(tree_key)->addr

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
	struct dlist_entry		siblings;
	struct dlist_entry		children;

	ofi_mr_handle_t			handle[1];
};

struct util_mr_mgr_tree_key {
	uint64_t	addr;
	size_t		length;
};

/* forward declarations. TODO: can we avoid them? */
static inline int util_mr_mgr_entry_get(struct ofi_mr_mgr *mgr,
					struct ofi_mr_region *entry);
static inline int util_mr_mgr_entry_put(struct ofi_mr_mgr *mgr,
					struct ofi_mr_region *entry);

static inline
struct util_mr_mgr_tree_key iov2tree_key(struct iovec *iov)
{
	struct util_mr_mgr_tree_key tree_key = {
		.addr	= IOV_BASE_2_KEY_ADDR(iov),
		.length	= iov->iov_len,
	};
	return tree_key;
}

static inline
struct iovec tree_key2iov(struct util_mr_mgr_tree_key *tree_key)
{
	struct iovec iov = {
		.iov_base	= KEY_ADDR_2_IOV_BASE(tree_key),
		.iov_len	= tree_key->length,
	};
	return iov;
}

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

static inline
void util_mr_mgr_entry_set_flags(struct ofi_mr_region *entry,
				 struct util_mr_mgr_entry_flags flags)
{
	entry->flags = flags;
}

static inline
void util_mr_mgr_entry_reset_flags(struct ofi_mr_region *entry)
{
	entry->flags.is_retired = 0;
	entry->flags.is_merged = 0;
	entry->flags.is_unmapped = 0;
}

static inline
int util_mr_mgr_entry_is_retired(struct ofi_mr_region *entry)
{
	return entry->flags.is_retired;
}

static inline
int util_mr_mgr_entry_is_merged(struct ofi_mr_region *entry)
{
	return entry->flags.is_merged;
}

static inline
int util_mr_mgr_entry_is_unmapped(struct ofi_mr_region *entry)
{
	return entry->flags.is_unmapped;
}

static inline
void util_mr_mgr_entry_set_retired(struct ofi_mr_region *entry)
{
	entry->flags.is_retired = 1;
}

static inline
void util_mr_mgr_entry_set_merged(struct ofi_mr_region *entry)
{
	entry->flags.is_merged = 1;
}

static inline
void util_mr_mgr_entry_set_unmapped(struct ofi_mr_region *entry)
{
	entry->flags.is_unmapped = 1;
}

/* x,y - struct iovec */
static int util_mr_mgr_find_overlapping_addr(void *x, void *y)
{
	struct util_mr_mgr_tree_key to_find = iov2tree_key(x);
	struct util_mr_mgr_tree_key to_compare = iov2tree_key(y);
	uint64_t to_find_end = to_find.addr + to_find.length - 1;
	uint64_t to_compare_end = to_compare.addr + to_compare.length - 1;

	/* format: (x_addr,  x_len) - (y_addr,  y_len) truth_value
	 *
	 * case 1: (0x1000, 0x1000) - (0x1400, 0x0800) true
	 * case 2: (0x1000, 0x1000) - (0x0C00, 0x0800) true
	 * case 3: (0x1000, 0x1000) - (0x1C00, 0x0800) true
	 * case 4: (0x1000, 0x1000) - (0x0C00, 0x2000) true
	 * case 5: (0x1000, 0x1000) - (0x0400, 0x0400) false
	 * case 6: (0x1000, 0x1000) - (0x2400, 0x0400) false
	 */
	if (!((to_find_end < to_compare.addr) ||
	      (to_compare_end < to_find.addr)))
		return 0;

	/* left */
	if (to_find.addr < to_compare.addr)
		return -1;

	return 1;
}

/* x,y - struct iovec */
static inline int util_mr_mgr_tree_key_comp(void *x, void *y)
{
	struct util_mr_mgr_tree_key to_insert = iov2tree_key(x);
	struct util_mr_mgr_tree_key to_compare = iov2tree_key(y);

	if (to_compare.addr == to_insert.addr) {
		return 0;
	} else if (to_insert.addr < to_compare.addr) {
		/* to the left */
		return -1;
	} else {
		/* to the right */
		return 1;
	}
}

static inline
int util_mr_mgr_can_subsume(struct iovec *x, struct iovec *y)
{
	struct util_mr_mgr_tree_key x_key = iov2tree_key(x);
	struct util_mr_mgr_tree_key y_key = iov2tree_key(y);

	return ((x_key.addr <= y_key.addr) &&
		((x_key.addr + x_key.length) >= (y_key.addr + y_key.length)));
}

static inline void
util_mr_mgr_attach_retired_entries_to_registration(struct ofi_mr_mgr *mgr,
						   struct dlist_entry *retired_entries,
						   struct ofi_mr_region *parent)
{
	struct ofi_mr_region *entry;
	struct dlist_entry *tmp;

	dlist_foreach_container_safe(retired_entries, struct ofi_mr_region,
				     entry, siblings, tmp) {
		dlist_remove(&entry->siblings);
		dlist_insert_tail(&entry->siblings, &parent->children);
		if (!dlist_empty(&entry->children)) {
			/* move the entry's children to the sibling tree
			 * and decrement the reference count */
			dlist_splice_tail(&parent->children,
					  &entry->children);
			util_mr_mgr_entry_put(mgr, entry);
		}
	}

	if (!dlist_empty(retired_entries))
		FI_WARN(&core_prov, FI_LOG_MR,
			"retired_entries not empty\n");

	util_mr_mgr_entry_get(mgr, parent);
}

static inline void
util_mr_mgr_remove_sibling_entries_from_tree(struct ofi_mr_mgr *mgr,
					     struct dlist_entry *list,
					     RbtHandle tree)
{
	RbtStatus rc;
	RbtIterator iter;
	struct ofi_mr_region *entry;

	dlist_foreach_container(list, struct ofi_mr_region,
				entry, siblings) {
		FI_DBG(&core_prov, FI_LOG_MR,
		       "removing key from tree, key=%"PRIu64":%"PRIu64"\n",
		       IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len);
		iter = rbtFind(tree, &entry->iov);
		if (OFI_UNLIKELY(!iter))
			FI_WARN(&core_prov, FI_LOG_MR,
				"key not found\n");

		rc = rbtErase(tree, iter);
		if (OFI_UNLIKELY(rc != RBT_STATUS_OK))
			FI_WARN(&core_prov, FI_LOG_MR,
				"could not remove entry from tree\n");
	}
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

static inline int util_mr_mgr_attr_sanity(struct ofi_mr_mgr_attr *attr)
{
	/* callbacks must be provided */
	if (!attr || !attr->registration_fn ||
	    !attr->deregistration_fn || !attr->compare_fn ||
	    (attr->hard_reg_limit > 0))
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

	mgr->state = OFI_MR_MGR_STATE_READY;

	return FI_SUCCESS;
fn2:
	rbtDelete(mgr->mr_inuse_tree);
	mgr->mr_inuse_tree = NULL;
fn1:
	return ret;
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
		       "entry (%p) unmapped, not inserting into stale %"PRIu64":%"PRIu64"\n",
		       entry, IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len);
		/* Should we return some other value? */
		return;
	}

	rc = rbtInsert(mgr->mr_stale_tree, &entry->iov, entry);
	if (rc != RBT_STATUS_OK) {
		FI_WARN(/*UTIL_MR_CACHE_GET_PROV(cache)*/&core_prov, FI_LOG_MR,
			"could not insert into stale rb tree,"
			" rc=%d key=%"PRIu64":%"PRIu64" entry=%p\n",
			rc, IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len, entry);

		util_mr_mgr_entry_destroy(mgr, entry);
	} else {
		FI_DBG(/*UTIL_MR_CACHE_GET_PROV(cache)*/&core_prov, FI_LOG_MR,
		       "inserted key=%"PRIu64":%"PRIu64" into stale\n",
		       IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len);

		util_mr_mgr_lru_enqueue(mgr, entry);
		switch (util_mr_mgr_entry_get_state(entry)) {
		case UTIL_MR_MGR_ENTRY_STATE_INUSE:
			util_mr_mgr_entry_set_state(entry,
						    UTIL_MR_MGR_ENTRY_STATE_STALE);
			break;
		default:
			FI_WARN(/*UTIL_MR_CACHE_GET_PROV(cache)*/&core_prov, FI_LOG_MR,
				"stale entry (%p) key=%"PRIu64":%"PRIu64" in bad state (%d)\n",
				entry, IOV_BASE_2_KEY_ADDR(&entry->iov),
				entry->iov.iov_len, (int)entry->state);
		}
	}

	return;
}

static inline
void util_mr_mgr_resolve_stale_entry_collision(struct ofi_mr_mgr *mgr,
					       RbtIterator found,
					       struct ofi_mr_region *entry)
{
	RbtStatus rc;
	struct ofi_mr_region *c_entry;
	struct dlist_entry *tmp;
	struct iovec *c_iov;
	DEFINE_LIST(to_destroy);
	RbtIterator iter = found;
	int add_new_entry = 1, cmp;

	FI_DBG(&core_prov, FI_LOG_MR,
	       "resolving collisions with entry (%p) key=%"PRIu64":%"PRIu64"\n",
	       entry, IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len);

	while (iter) {
		rbtKeyValue(mgr->mr_stale_tree, iter, (void **)&c_iov,
			    (void **)&c_entry);

		cmp = util_mr_mgr_find_overlapping_addr(&entry->iov, c_iov);
		if (cmp != 0)
			break;

		if (util_mr_mgr_can_subsume(&entry->iov, c_iov) ||
		    (entry->iov.iov_len > c_iov->iov_len)) {
			FI_DBG(&core_prov, FI_LOG_MR,
			       "adding stale entry (%p) to destroy list,"
			       " key=%"PRIu64":%"PRIu64"\n", c_entry,
			       IOV_BASE_2_KEY_ADDR(c_iov), c_iov->iov_len);
			dlist_insert_tail(&c_entry->siblings, &to_destroy);
		} else {
			add_new_entry = 0;
		}

		iter = rbtNext(mgr->mr_stale_tree, iter);
	}

	/* TODO I can probably do this in a single sweep, avoiding a second
	 * pass and incurring n lg n removal time
	 */
	dlist_foreach_container_safe(&to_destroy, struct ofi_mr_region,
				     c_entry, siblings, tmp) {
		FI_DBG(&core_prov, FI_LOG_MR,
		       "removing key from tree, entry %p key=%"PRIu64":%"PRIu64"\n",
		       c_entry, IOV_BASE_2_KEY_ADDR(&c_entry->iov), c_entry->iov.iov_len);
		iter = rbtFind(mgr->mr_stale_tree, &c_entry->iov);
		if (OFI_UNLIKELY(!iter))
			FI_WARN(&core_prov, FI_LOG_MR,
				"key not found\n");

		rc = rbtErase(mgr->mr_stale_tree, iter);
		if (OFI_UNLIKELY(rc != RBT_STATUS_OK))
			FI_WARN(&core_prov, FI_LOG_MR,
				"could not remove entry from tree\n");

		util_mr_mgr_lru_remove(mgr, c_entry);
		dlist_remove(&c_entry->siblings);
		util_mr_mgr_entry_destroy(mgr, c_entry);
	}
	if (OFI_UNLIKELY(!dlist_empty(&to_destroy)))
		FI_WARN(&core_prov, FI_LOG_MR,
			"to_destroy not empty\n");

	if (add_new_entry) {
		util_mr_mgr_insert_entry_into_stale(mgr, entry);
	} else {
		/* stale entry is larger than this one
		 * so lets just toss this entry out
		 */
		FI_DBG(&core_prov, FI_LOG_MR,
		       "larger entry already exists, to_destroy.key=%"PRIu64":%"PRIu64"\n",
		       IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len);

		util_mr_mgr_entry_destroy(mgr, entry);
	}
}

static inline int util_mr_mgr_entry_get(struct ofi_mr_mgr *mgr,
					struct ofi_mr_region *entry)
{
	OFI_UNUSED(mgr);
	FI_DBG(&core_prov, FI_LOG_MR,
	       "Up ref cnt on entry %p\n", entry);
	return ofi_atomic_inc32(&entry->use_cnt);
}

static inline int util_mr_mgr_entry_put(struct ofi_mr_mgr *mgr,
					struct ofi_mr_region *entry)
{
	RbtIterator iter;
	int rc;
	int ret = FI_SUCCESS;
	RbtIterator found;
	struct ofi_mr_region *parent = NULL;
	struct dlist_entry *next;

	/*if (cache->attr.lazy_deregistration)
	  util_mr_cache_clear_notifier_events(cache);*/

	FI_DBG(&core_prov, FI_LOG_MR,
	       "Decrease ref cnt on entry %p\n", entry);

	if (ofi_atomic_dec32(&entry->use_cnt) == 0) {
		next = entry->siblings.next;
		dlist_remove(&entry->children);
		dlist_remove(&entry->siblings);

		/* if this is the last child to deallocate,
		 * release the reference to the parent
		 */
		if (next != &entry->siblings && dlist_empty(next)) {
			parent = container_of(next, struct ofi_mr_region,
					      children);
			ret = util_mr_mgr_entry_put(mgr, parent);
			if (OFI_UNLIKELY(ret))
				FI_WARN(&core_prov, FI_LOG_MR,
					"failed to release reference to parent, "
					"parent=%p refs=%d\n",
					parent, ofi_atomic_get32(&parent->use_cnt));
		}

		if (!util_mr_mgr_entry_is_retired(entry)) {
			iter = rbtFind(mgr->mr_inuse_tree, &entry->iov);
			if (OFI_UNLIKELY(!iter)) {
				FI_WARN(&core_prov, FI_LOG_MR,
					"failed to find entry in the inuse cache\n");
			} else {
				rc = rbtErase(mgr->mr_inuse_tree, iter);
				if (OFI_UNLIKELY(rc != RBT_STATUS_OK))
					FI_WARN(&core_prov, FI_LOG_MR,
						"failed to erase lru entry from stale tree\n");
			}
		}

		/* if we are doing lazy dereg and the entry
		 * isn't retired, put it in the stale cache
		 */
		if (mgr->attr.lazy_deregistration &&
		    !util_mr_mgr_entry_is_retired(entry)) {
			FI_DBG(&core_prov, FI_LOG_MR,
			       "moving key %"PRIu64":%"PRIu64" to stale (entry %p)\n",
			       IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len, entry);

			found = rbtFindLeftmost(mgr->mr_stale_tree, &entry->iov,
						util_mr_mgr_find_overlapping_addr);
			if (found) {
				/* one or more stale entries would overlap with this
				 * new entry. We need to resolve these collisions by dropping
				 * registrations
				 */
				util_mr_mgr_resolve_stale_entry_collision(mgr,
									  found,
									  entry);
			} else {
				/* if not found, ... */
				util_mr_mgr_insert_entry_into_stale(mgr, entry);
			}
		} else {
			/* if retired or not using lazy registration */
			FI_DBG(&core_prov, FI_LOG_MR,
			       "destroying entry, key=%"PRIu64":%"PRIu64" (entry %p)\n",
			       IOV_BASE_2_KEY_ADDR(&entry->iov), entry->iov.iov_len, entry);

			util_mr_mgr_entry_destroy(mgr, entry);
		}
	}

	return ret;
}

static int util_mr_mgr_flush_ex(struct ofi_mr_mgr *mgr, size_t flush_count)
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

static int util_mr_mgr_flush(struct ofi_mr_mgr *mgr)
{
	if (OFI_UNLIKELY(mgr->state != OFI_MR_MGR_STATE_READY))
		return -FI_EINVAL;

	util_mr_mgr_flush_ex(mgr, mgr->attr.hard_reg_limit);

	return FI_SUCCESS;
}


static int util_mr_mgr_search_inuse(struct ofi_mr_mgr *mgr,
				    struct iovec *iov,
				    struct ofi_mr_region **entry)
{
	int ret = FI_SUCCESS, cmp;
	RbtIterator iter;
	struct iovec *found_iov, new_iov;
	struct util_mr_mgr_tree_key new_key;
	struct ofi_mr_region *found_entry;
	uint64_t new_end, found_end;
	DEFINE_LIST(retired_entries);

	/*if (cache->attr.lazy_deregistration)
		util_mr_cache_clear_notifier_events(cache);*/

	/* first we need to find an entry that overlaps with this one.
	 * care should be taken to find the left most entry that overlaps
	 * with this entry since the entry we are searching for might overlap
	 * many entries and the tree may be left or right balanced
	 * at the head
	 */
	iter = rbtFindLeftmost(mgr->mr_inuse_tree, (void *)iov,
			       util_mr_mgr_find_overlapping_addr);
	if (!iter) {
		FI_DBG(&core_prov, FI_LOG_MR,
		       "could not find key in inuse, key=%"PRIu64":%"PRIu64"\n",
		       IOV_BASE_2_KEY_ADDR(iov), iov->iov_len);
		return -FI_ENOENT;
	}

	rbtKeyValue(mgr->mr_inuse_tree, iter, (void **)&found_iov,
		    (void **)&found_entry);

	FI_DBG(&core_prov, FI_LOG_MR,
	       "found a key that matches the search criteria, "
	       "found=%"PRIu64":%"PRIu64" key=%"PRIu64":%"PRIu64"\n",
	       IOV_BASE_2_KEY_ADDR(found_iov), found_iov->iov_len,
	       IOV_BASE_2_KEY_ADDR(iov), iov->iov_len);

	/* if the entry that we've found completely subsumes
	 * the requested entry, just return a reference to
	 * that existing registration
	 */
	if (util_mr_mgr_can_subsume(found_iov, iov)) {
		FI_DBG(&core_prov, FI_LOG_MR,
		       "found an entry that subsumes the request, "
		       "existing=%"PRIu64":%"PRIu64" key=%"PRIu64":%"PRIu64"entry %p\n",
		       IOV_BASE_2_KEY_ADDR(found_iov), found_iov->iov_len,
		       IOV_BASE_2_KEY_ADDR(iov), iov->iov_len, found_entry);
		*entry = found_entry;
		util_mr_mgr_entry_get(mgr, found_entry);
		return FI_SUCCESS;
	}

	/* otherwise, iterate from the existing entry until we can no longer
	 * find an entry that overlaps with the new registration and remove
	 * and retire each of those entries.
	 */
	new_key.addr = MIN(IOV_BASE_2_KEY_ADDR(found_iov),
			   IOV_BASE_2_KEY_ADDR(iov));
	new_end = IOV_BASE_2_KEY_ADDR(iov) + iov->iov_len;
	while (iter) {
		rbtKeyValue(mgr->mr_inuse_tree, iter, (void **)&found_iov,
			    (void **)&found_entry);

		cmp = util_mr_mgr_find_overlapping_addr(found_iov, iov);
		FI_DBG(&core_prov, FI_LOG_MR,
		       "candidate: key=%"PRIu64":%"PRIu64" result=%d\n",
		       IOV_BASE_2_KEY_ADDR(found_iov), found_iov->iov_len, cmp);
		if (cmp != 0)
			break;

		/* compute new ending address */
		found_end = IOV_BASE_2_KEY_ADDR(found_iov) + found_iov->iov_len;

		/* mark the entry as retired */
		FI_DBG(&core_prov, FI_LOG_MR,
		       "retiring entry, key=%"PRIu64":%"PRIu64" entry %p\n",
		       IOV_BASE_2_KEY_ADDR(found_iov), found_iov->iov_len, found_entry);
		util_mr_mgr_entry_set_retired(found_entry);
		dlist_insert_tail(&found_entry->siblings, &retired_entries);

		iter = rbtNext(mgr->mr_inuse_tree, iter);
	}
	/* Since our new key might fully overlap every other entry in the tree,
	 * we need to take the maximum of the last entry and the new entry
	 */
	new_key.length = MAX(found_end, new_end) - new_key.addr;

	/* remove retired entries from tree */
	FI_DBG(&core_prov, FI_LOG_MR,
	       "removing retired entries from inuse tree\n");
	util_remove_sibling_entries_from_tree(
		mgr, &retired_entries, mgr->mr_inuse_tree);

	/* create new registration */
	FI_DBG(&core_prov, FI_LOG_MR,
	       "creating a new merged registration, key=%"PRIu64":%"PRIu64"\n",
	       new_key.addr, new_key.length);

	new_iov = tree_key2iov(&new_key);
	ret = util_mr_cache_create_registration(mgr, &new_iov, entry);
	if (ret) {
		/* If we get here, one of two things have happened.
		 * Either some part of the new merged registration was
		 * unmapped (i.e., freed by user) or the merged
		 * registration failed for some other reason. 
		 * The first case is a user error
		 * (which they should have been warned about by
		 * the notifier), and the second case is always
		 * possible.  Neither case is a problem.  The entries
		 * above have been retired, and here we return the
		 * error */
		FI_DBG(&core_prov, FI_LOG_MR,
		       "failed to create merged registration,"
		       " key=%"PRIu64":%"PRIu64"\n",
		       new_key.addr, new_key.length);
		return ret;
	}

	FI_DBG(&core_prov, FI_LOG_MR,
	       "created a new merged registration, key=%"PRIu64":%"PRIu64" entry %p\n",
	       new_key.addr, new_key.length, *entry);

	util_mr_mgr_entry_set_merged(*entry);

	/* move retired entries to the head of the new entry's child list */
	if (!dlist_empty(&retired_entries))
		util_attach_retired_entries_to_registration(
		    mgr, &retired_entries, *entry);

	return ret;
}

static int util_mr_mgr_search_stale(struct ofi_mr_mgr *mgr,
				    struct iovec *iov,
				    struct ofi_mr_region **entry)
{
	int ret;
	RbtStatus rc;
	RbtIterator iter;
	struct iovec *mr_iov;
	struct ofi_mr_region *mr_entry, *tmp;

	/*if (mgr->attr.lazy_deregistration)
	  util_mr_cache_clear_notifier_events(cache);*/

	FI_DBG(&core_prov, FI_LOG_MR,
	       "searching for stale entry, key=%"PRIu64":%"PRIu64"\n",
	       IOV_BASE_2_KEY_ADDR(iov), iov->iov_len);

	iter = rbtFindLeftmost(mgr->mr_stale_tree, (void *)iov,
			       util_mr_mgr_find_overlapping_addr);
	if (!iter)
		return -FI_ENOENT;

	rbtKeyValue(mgr->mr_stale_tree, iter, (void **)&mr_iov,
			(void **)&mr_entry);

	FI_DBG(&core_prov, FI_LOG_MR,
	       "found a matching entry, found.key=%"PRIu64":%"PRIu64
	       "key=%"PRIu64":%"PRIu64"\n",
	       IOV_BASE_2_KEY_ADDR(mr_iov), mr_iov->iov_len,
	       IOV_BASE_2_KEY_ADDR(iov), iov->iov_len);

	/* if the entry that we've found completely subsumes
	 * the requested entry, just return a reference to
	 * that existing registration
	 */
	if (util_mr_mgr_can_subsume(mr_iov, iov)) {
	    ret = util_mr_mgr_search_inuse(mgr, mr_iov, &tmp);
		if (ret == FI_SUCCESS) {
			/* if we found an entry in the inuse tree
			 * in this manner, it means that there was
			 * an entry either overlapping or contiguous
			 * with the stale entry in the inuse tree, and
			 * a new entry has been made and saved to tmp.
			 * The old entry (mr_entry) should be destroyed
			 * now as it is no longer needed.
			 */
			FI_DBG(&core_prov, FI_LOG_MR,
			       "removing entry from stale key=%"PRIu64":%"PRIu64"\n",
			       IOV_BASE_2_KEY_ADDR(mr_iov), mr_iov->iov_len);

			rc = rbtErase(mgr->mr_stale_tree, iter);
			if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
				FI_WARN(&core_prov, FI_LOG_MR,
					"failed to erase entry from stale tree\n");
			} else {
				util_mr_mgr_lru_remove(mgr, mr_entry);
				util_mr_mgr_entry_destroy(mgr, mr_entry);
			}

			*entry = tmp;
		} else {
			FI_DBG(&core_prov, FI_LOG_MR,
			       "removing entry (%p) from stale and migrating to inuse,"
			       " key=%"PRIu64":%"PRIu64"\n",
			       mr_entry, IOV_BASE_2_KEY_ADDR(mr_iov), mr_iov->iov_len);
			rc = rbtErase(mgr->mr_stale_tree, iter);
			if (OFI_UNLIKELY(rc != RBT_STATUS_OK))
				FI_WARN(&core_prov, FI_LOG_MR,
					"failed to erase entry (%p) from stale tree\n",
					mr_entry);

			util_mr_mgr_lru_remove(mgr, mr_entry);
			/* if we made it to this point, there weren't
			 * any entries in the inuse tree that would
			 * have overlapped with this entry
			 */
			rc = rbtInsert(mgr->mr_inuse_tree,
					&mr_entry->iov, mr_entry);
			if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
				FI_WARN(&core_prov, FI_LOG_MR,
					"failed to insert entry into inuse tree\n");
			}

			ofi_atomic_set32(&mr_entry->use_cnt, 1);

			*entry = mr_entry;
		}

		return FI_SUCCESS;
	}

	FI_DBG(&core_prov, FI_LOG_MR,
	       "could not use matching entry, found=%"PRIu64":%"PRIu64"\n",
	       IOV_BASE_2_KEY_ADDR(mr_iov), mr_iov->iov_len);

	return -FI_ENOENT;
}

void ofi_mgr_mgr_cleanup(struct ofi_mr_mgr *mgr)
{
	if (mgr->state != OFI_MR_MGR_STATE_READY)
		return;
	/*
	 * Remove all of the stale entries from the cache
	 */
	util_mr_mgr_flush(mgr);

	/*
	 * if there are still elements in the cache after the flush,
	 *   then someone forgot to deregister memory.
	 *   We probably shouldn't destroy the cache at this point.
	 */
	/*TODO: Deal with inuse elemnts*/

	/* destroy the tree */
	rbtDelete(mgr->mr_inuse_tree);
	mgr->mr_inuse_tree = NULL;

	/* stale have been flushed already, so just destroy the tree */
	if (mgr->attr.lazy_deregistration) {
		rbtDelete(mgr->mr_stale_tree);
		mgr->mr_stale_tree = NULL;
	}

	mgr->state = OFI_MR_MGR_STATE_UNINITIALIZED;
}
