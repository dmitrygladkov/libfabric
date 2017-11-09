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

#include <fi_util.h>
#include <inttypes.h>

typedef unsigned long long int util_cache_entry_state_t;
/* These are used for entry state and should be unique */
#define UTIL_CES_INUSE       (1ULL << 8)    /* in use */
#define UTIL_CES_STALE       (2ULL << 8)    /* cached for possible reuse */
#define UTIL_CES_STATE_MASK  (0xFULL << 8)

typedef unsigned long long int util_cache_entry_flag_t;
/* One or more of these can be combined with the above */
#define UTIL_CE_RETIRED     (1ULL << 61)   /* in use, but not to be reused */
#define UTIL_CE_MERGED      (1ULL << 62)   /* merged entry, i.e., not
					    * an original request from
					    * fi_mr_reg */
#define UTIL_CE_UNMAPPED    (1ULL << 63)   /* at least 1 page of the
					    * entry has been unmapped
					    * by the OS */

/**
 * @brief structure for containing the fields relevant to the memory cache key
 *
 * @var   address  base address of the memory region
 * @var   address  length of the memory region
 */
struct util_mr_cache_key {
	uint64_t address;
	uint64_t length;
};

/**
 * @brief gnix memory registration cache entry
 *
 * @var   state      state of the memory registration cache entry
 * @var   key        memory registration cache key
 * @var   domain     provider domain associated with the memory registration
 * @var   ref_cnt    reference counting for the cache
 * @var   lru_entry  lru list entry
 * @var   siblings   list of sibling entries
 * @var   children   list of subsumed child entries
 * @var   mr         provider memory registration descriptor
 */
struct util_mr_cache_entry {
	util_cache_entry_state_t state;
	struct util_mr_cache_key key;
	ofi_atomic32_t ref_cnt;
	struct dlist_entry lru_entry;
	struct dlist_entry siblings;
	struct dlist_entry children;
	uint64_t mr[0];
};

static inline int util_mr_cache_entry_put(struct util_mr_cache *cache,
					  struct util_mr_cache_entry *entry);

static inline int util_mr_cache_entry_get(struct util_mr_cache *cache,
					  struct util_mr_cache_entry *entry);

static inline int util_mr_cache_entry_destroy(struct util_mr_cache *cache,
					      struct util_mr_cache_entry *entry);

static int util_mr_cache_create_registration(struct util_mr_cache *cache,
					     uint64_t address, uint64_t length,
					     struct util_mr_cache_entry **entry,
					     struct util_mr_cache_key *key,
					     struct util_fi_reg_context *fi_reg_context);

/* default attributes for new caches */
struct util_mr_cache_attr default_mr_cache_attr = {
	.soft_reg_limit      = 4096,
	.hard_reg_limit      = -1,
	.hard_stale_limit    = 128,
	.lazy_deregistration = 1,
};

/* Functions for using and manipulating cache entry state */
static inline util_cache_entry_state_t
util_entry_get_state(struct util_mr_cache_entry *entry)
{
	return entry->state & UTIL_CES_STATE_MASK;
}

static inline void util_entry_set_state(struct util_mr_cache_entry *entry,
					util_cache_entry_state_t state)
{
	entry->state = (entry->state & ~UTIL_CES_STATE_MASK) |
		(state & UTIL_CES_STATE_MASK);
}

static inline void util_entry_reset_state(struct util_mr_cache_entry *entry)
{
	entry->state = 0ULL;
}

static inline int util_entry_is_flag(struct util_mr_cache_entry *entry,
				     util_cache_entry_flag_t flag)
{
	return ((entry->state & flag) != 0);
}

static inline void util_entry_set_flag(struct util_mr_cache_entry *entry,
				    util_cache_entry_flag_t flag)
{
	entry->state = entry->state | flag;
}

static inline int util_entry_is_retired(struct util_mr_cache_entry *entry)
{
	return util_entry_is_flag(entry, UTIL_CE_RETIRED);
}

static inline int util_entry_is_merged(struct util_mr_cache_entry *entry)
{
	return util_entry_is_flag(entry, UTIL_CE_MERGED);
}

static inline int util_entry_is_unmapped(struct util_mr_cache_entry *entry)
{
	return util_entry_is_flag(entry, UTIL_CE_UNMAPPED);
}

static inline void util_entry_set_retired(struct util_mr_cache_entry *entry)
{
	util_entry_set_flag(entry, UTIL_CE_RETIRED);
}

static inline void util_entry_set_merged(struct util_mr_cache_entry *entry)
{
	util_entry_set_flag(entry, UTIL_CE_MERGED);
}

static inline void util_entry_set_unmapped(struct util_mr_cache_entry *entry)
{
	util_entry_set_flag(entry, UTIL_CE_UNMAPPED);
}

/**
 * Key comparison function for finding overlapping memory
 * registration cache entries
 *
 * @param[in] x key to be inserted or found
 * @param[in] y key to be compared against
 *
 * @return    -1 if it should be positioned at the left, 0 if it overlaps,
 *             1 otherwise
 */
static int util_find_overlapping_addr(void *x, void *y)
{
	struct util_mr_cache_key *to_find  = (struct util_mr_cache_key *)x;
	struct util_mr_cache_key *to_compare = (struct util_mr_cache_key *)y;
	uint64_t to_find_end = to_find->address + to_find->length;
	uint64_t to_compare_end = to_compare->address + to_compare->length;

	/* format: (x_addr,  x_len) - (y_addr,  y_len) truth_value
	 *
	 * case 1: (0x1000, 0x1000) - (0x1400, 0x0800) true
	 * case 2: (0x1000, 0x1000) - (0x0C00, 0x0800) true
	 * case 3: (0x1000, 0x1000) - (0x1C00, 0x0800) true
	 * case 4: (0x1000, 0x1000) - (0x0C00, 0x2000) true
	 * case 5: (0x1000, 0x1000) - (0x0400, 0x0400) false
	 * case 6: (0x1000, 0x1000) - (0x2400, 0x0400) false
	 */
	if (!((to_find_end < to_compare->address) ||
	      (to_compare_end < to_find->address)))
		return 0;

	/* left */
	if (to_find->address < to_compare->address)
		return -1;

	return 1;
}

/**
 * Key comparison function for memory registration caches
 *
 * @param[in] x key to be inserted or found
 * @param[in] y key to be compared against
 *
 * @return    -1 if it should be positioned at the left, 0 if the same,
 *             1 otherwise
 */
static inline int util_mr_cache_key_comp(void *x, void *y)
{
	struct util_mr_cache_key *to_insert  = (struct util_mr_cache_key *)x;
	struct util_mr_cache_key *to_compare = (struct util_mr_cache_key *)y;

	if (to_compare->address == to_insert->address)
		return 0;

	/* to the left */
	if (to_insert->address < to_compare->address)
		return -1;

	/* to the right */
	return 1;
}

/**
 * Helper function for matching the exact key entry
 *
 * @param entry     memory registration cache key
 * @param to_match  memory registration cache key
 * @return 1 if match, otherwise 0
 */
static inline int util_match_exact_key(struct util_mr_cache_key *entry, 
				    struct util_mr_cache_key *to_match)
{
	return (entry->address == to_match->address) &&
	       (entry->length == to_match->length);
}

/**
 * dlist search function for matching the exact memory registration key
 *
 * @param entry memory registration cache entry
 * @param match memory registration cache key
 * @return 1 if match, otherwise 0
 */
static inline int util_mr_exact_key(struct dlist_entry *entry,
				    const void *match)
{
	struct util_mr_cache_entry *x =
		container_of(entry, struct util_mr_cache_entry,
			     siblings);
	struct util_mr_cache_key *y = (struct util_mr_cache_key *)match;

	return util_match_exact_key(&x->key, y);
}

/**
 * Helper function to determine if one key subsumes another
 *
 * @param x  gnix_mr_cache_key
 * @param y  gnix_mr_cache_key
 * @return 1 if x subsumes y, 0 otherwise
 */
static inline int util_can_subsume(struct util_mr_cache_key *x,
				   struct util_mr_cache_key *y)
{
	return (x->address <= y->address) &&
			((x->address + x->length) >=
					(y->address + y->length));
}

static inline void
util_attach_retired_entries_to_registration(struct util_mr_cache *cache,
					    struct dlist_entry *retired_entries,
					    struct util_mr_cache_entry *parent)
{
	struct util_mr_cache_entry *entry;
	struct dlist_entry *tmp;

	dlist_foreach_container_safe(retired_entries,
				     struct util_mr_cache_entry,
				     entry, siblings, tmp) {
		dlist_remove(&entry->siblings);
		dlist_insert_tail(&entry->siblings,
				  &parent->children);
		if (!dlist_empty(&entry->children)) {
			/* move the entry's children to the sibling tree
			 * and decrement the reference count */
			dlist_splice_tail(&parent->children,
					  &entry->children);
			util_mr_cache_entry_put(cache, entry);
		}
	}

	if (!dlist_empty(retired_entries))
		FI_WARN(&core_prov, FI_LOG_MR, "retired_entries not empty\n");

	util_mr_cache_entry_get(cache, parent);
}

static inline void
util_remove_sibling_entries_from_tree(struct util_mr_cache *cache,
				      struct dlist_entry *list,
				      RbtHandle tree)
{
	RbtStatus rc;
	RbtIterator iter;
	struct util_mr_cache_entry *entry;

	dlist_foreach_container(list, struct util_mr_cache_entry,
				entry, siblings) {
		FI_DBG(&core_prov,FI_LOG_MR,
			   "removing key from tree, key=%"PRIu64":%"PRIu64"\n",
			   entry->key.address, entry->key.length);
		iter = rbtFind(tree, &entry->key);
		if (OFI_UNLIKELY(!iter))
			FI_WARN(&core_prov, FI_LOG_MR, "key not found\n");

		rc = rbtErase(tree, iter);
		if (OFI_UNLIKELY(rc != RBT_STATUS_OK))
			FI_WARN(&core_prov, FI_LOG_MR,
				   "could not remove entry from tree\n");
	}
}

/**
 * Pushes an entry into the LRU cache. No limits are maintained here as
 *   the hard_stale_limit attr value will directly limit the lru size
 *
 * @param[in] cache  a memory registration cache object
 * @param[in] entry  a memory registration cache entry
 *
 * @return           FI_SUCCESS, always
 */
static inline int util_mr_cache_lru_enqueue(struct util_mr_cache *cache,
					    struct util_mr_cache_entry *entry)
{
	dlist_insert_tail(&entry->lru_entry, &cache->lru_head);
	return FI_SUCCESS;
}

/**
 * Pops an registration cache entry from the lru cache.
 *
 * @param[in] cache  a memory registration cache
 * @param[in] entry  a memory registration cache entry
 *
 * @return           FI_SUCCESS, on success
 * @return           -FI_ENOENT, on empty LRU
 */
static inline int util_mr_cache_lru_dequeue(struct util_mr_cache *cache,
					    struct util_mr_cache_entry **entry)
{
	if (OFI_UNLIKELY(dlist_empty(&cache->lru_head))) {
		*entry = NULL;
		return -FI_ENOENT;
	}
	/* Takes the first entry from the LRU */
	dlist_pop_front(&cache->lru_head,
			struct util_mr_cache_entry,
			*entry, lru_entry);

	return FI_SUCCESS;
}

/**
 * Removes a particular registration cache entry from the lru cache.
 *
 * @param[in] cache  a memory registration cache
 * @param[in] entry  a memory registration cache entry
 *
 * @return           FI_SUCCESS, on success
 * @return           -FI_ENOENT, on empty LRU
 */
static inline int util_mr_cache_lru_remove(struct util_mr_cache *cache,
					   struct util_mr_cache_entry *entry)
{
	dlist_remove(&entry->lru_entry);
	return FI_SUCCESS;
}

/**
 * Destroys the memory registration cache entry and deregisters the memory
 *   region with provider
 *
 * @param[in] entry  a memory registration cache entry
 *
 * @return           return code from callbacks
 */
static inline int
util_mr_cache_entry_destroy(struct util_mr_cache *cache,
			    struct util_mr_cache_entry *entry)
{
	int rc;

	rc = cache->attr.dereg_callback(entry->mr,
					cache->attr.dereg_context);
	if (!rc) {
		/*if (!util_entry_is_unmapped(entry)) { UNMONITOR!
		}*/
		util_entry_reset_state(entry);
		free(entry);
	} else {
		FI_INFO(&core_prov, FI_LOG_MR, "failed to deregister memory"
			  " region with callback, "
			  "cache_entry=%p ret=%i\n", entry, rc);
	}

	return rc;
}

static inline
int util_insert_entry_into_stale(struct util_mr_cache *cache,
				 struct util_mr_cache_entry *entry)
{
	RbtStatus rc;
	int ret = FI_SUCCESS;

	if (util_entry_is_unmapped(entry)) {
		FI_DBG(&core_prov, FI_LOG_MR, "entry (%p) unmapped, not inserting"
			   " into stale %"PRIu64":%"PRIu64"\n", entry,
			   entry->key.address, entry->key.length);
		/* Should we return some other value? */
		return ret;
	}

	rc = rbtInsert(cache->stale.rb_tree,
			&entry->key,
			entry);
	if (rc != RBT_STATUS_OK) {
		FI_WARN(&core_prov, FI_LOG_MR,
			"could not insert into stale rb tree,"
			" rc=%d key.address=%"PRIu64" key.length=%"PRIu64
			" entry=%p\n",
			rc, entry->key.address, entry->key.length, entry);

		ret = util_mr_cache_entry_destroy(cache, entry);
	} else {
		FI_DBG(&core_prov, FI_LOG_MR,
		       "inserted key=%"PRIu64":%"PRIu64" into stale\n",
		       entry->key.address, entry->key.length);

		util_mr_cache_lru_enqueue(cache, entry);
		ofi_atomic_inc32(&cache->stale.elements);
		switch (util_entry_get_state(entry)) {
		case  UTIL_CES_INUSE:
			util_entry_set_state(entry, UTIL_CES_STALE);
			break;
		default:
			FI_WARN(&core_prov, FI_LOG_MR,
				"stale entry (%p) %"PRIu64":%"PRIu64" in bad"
				" state (%llu)\n", entry,
				entry->key.address, entry->key.length,
				entry->state);
		}
	}

	return ret;
}

static inline
void util_resolve_stale_entry_collision(struct util_mr_cache *cache,
					RbtIterator found,
					struct util_mr_cache_entry *entry)
{
	RbtStatus rc;
	struct util_mr_cache_entry *c_entry;
	struct dlist_entry *tmp;
	struct util_mr_cache_key *c_key;
	int ret;
	DEFINE_LIST(to_destroy);
	RbtIterator iter = found;
	int add_new_entry = 1, cmp;

	FI_DBG(&core_prov, FI_LOG_MR,
	       "resolving collisions with entry (%p) %"PRIu64":%"PRIu64"\n",
	       entry, entry->key.address, entry->key.length);

	while (iter) {
		rbtKeyValue(cache->stale.rb_tree, iter, (void **) &c_key,
			    (void **) &c_entry);

		cmp = util_find_overlapping_addr(&entry->key, c_key);
		if (cmp != 0)
			break;

		if (util_can_subsume(&entry->key, c_key) ||
		    (entry->key.length > c_key->length)) {
			FI_DBG(&core_prov, FI_LOG_MR,
			       "adding stale entry (%p) to destroy list,"
			       " key=%"PRIu64":%"PRIu64"\n", c_entry,
			       c_key->address, c_key->length);
			dlist_insert_tail(&c_entry->siblings, &to_destroy);
		} else {
			add_new_entry = 0;
		}

		iter = rbtNext(cache->stale.rb_tree, iter);
	}

	/* TODO I can probably do this in a single sweep, avoiding a second
	 * pass and incurring n lg n removal time
	 */
	dlist_foreach_container_safe(&to_destroy, struct util_mr_cache_entry,
				     c_entry, siblings, tmp)
	{
		FI_DBG(&core_prov, FI_LOG_MR, "removing key from tree, entry %p"
		       " key=%"PRIu64":%"PRIu64"\n", c_entry,
		       c_entry->key.address, c_entry->key.length);
		iter = rbtFind(cache->stale.rb_tree, &c_entry->key);
		if (OFI_UNLIKELY(!iter))
			FI_WARN(&core_prov, FI_LOG_MR, "key not found\n");

		rc = rbtErase(cache->stale.rb_tree,
						iter);
		if (OFI_UNLIKELY(rc != RBT_STATUS_OK))
			FI_WARN(&core_prov, FI_LOG_MR,
				"could not remove entry from tree\n");

		if (util_mr_cache_lru_remove(cache, c_entry) != FI_SUCCESS)
			FI_WARN(&core_prov, FI_LOG_MR, "Failed to remove entry"
				" from lru list (%p)\n", c_entry);
		ofi_atomic_dec32(&cache->stale.elements);
		dlist_remove(&c_entry->siblings);
		util_mr_cache_entry_destroy(cache, c_entry);
	}
	if (OFI_UNLIKELY(!dlist_empty(&to_destroy)))
		FI_WARN(&core_prov, FI_LOG_MR, "to_destroy not empty\n");

	if (add_new_entry) {
		ret = util_insert_entry_into_stale(cache, entry);
		if (ret)
			FI_WARN(&core_prov, FI_LOG_MR,
				"Failed to insert subsumed MR "
				" entry (%p) into stale list\n",
				entry);
	} else {
		/* stale entry is larger than this one
		 * so lets just toss this entry out
		 */
		FI_DBG(&core_prov, FI_LOG_MR,
		       "larger entry already exists,"
		       " to_destroy=%"PRIu64":%"PRIu64"\n",
		       entry->key.address, entry->key.length);

		ret = util_mr_cache_entry_destroy(cache, entry);
		if (ret)
			FI_WARN(&core_prov, FI_LOG_MR,
				"failed to destroy a "
				"registration, entry=%p grc=%d\n",
				c_entry, ret);
	}
}

/**
 * Increments the reference count on a memory registration cache entry
 *
 * @param[in] cache  gnix memory registration cache
 * @param[in] entry  a memory registration cache entry
 *
 * @return           reference count for the registration
 */
static inline int
util_mr_cache_entry_get(struct util_mr_cache *cache,
			struct util_mr_cache_entry *entry)
{
	return ofi_atomic_inc32(&entry->ref_cnt);
}

/**
 * Decrements the reference count on a memory registration cache entry
 *
 * @param[in] cache  gnix memory registration cache
 * @param[in] entry  a memory registration cache entry
 *
 * @return           return code from dereg callback
 */
static inline
int util_mr_cache_entry_put(struct util_mr_cache *cache,
			    struct util_mr_cache_entry *entry)
{
	RbtIterator iter;
	int rc;
	int grc = FI_SUCCESS;
	RbtIterator found;
	struct util_mr_cache_entry *parent = NULL;
	struct dlist_entry *next;

	if (cache->attr.lazy_deregistration) {
	    /*__clear_notifier_events(cache);
		
		*/
	}

	if (ofi_atomic_dec32(&entry->ref_cnt) == 0) {
		next = entry->siblings.next;
		dlist_remove(&entry->children);
		dlist_remove(&entry->siblings);

		/* if this is the last child to deallocate,
		 * release the reference to the parent
		 */
		if (next != &entry->siblings && dlist_empty(next)) {
			parent = container_of(next, struct util_mr_cache_entry,
					      children);
			grc = util_mr_cache_entry_put(cache, parent);
			if (OFI_UNLIKELY(grc != FI_SUCCESS))
				FI_WARN(&core_prov, FI_LOG_MR,
					"failed to release reference to parent, "
					"parent=%p refs=%d\n",
					parent, ofi_atomic_get32(&parent->ref_cnt));
		}

		ofi_atomic_dec32(&cache->inuse.elements);

		if (!util_entry_is_retired(entry)) {
			iter = rbtFind(cache->inuse.rb_tree, &entry->key);
			if (OFI_UNLIKELY(!iter)) {
				FI_WARN(&core_prov, FI_LOG_MR,
						"failed to find entry in the inuse cache\n");
			} else {
				rc = rbtErase(cache->inuse.rb_tree, iter);
				if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
					FI_WARN(&core_prov, FI_LOG_MR,
						 "failed to erase lru entry"
						 " from stale tree\n");
				}
			}
		}

		/* if we are doing lazy dereg and the entry
		 * isn't retired, put it in the stale cache
		 */
		if (cache->attr.lazy_deregistration && !(util_entry_is_retired(entry))) {
			FI_DBG(&core_prov, FI_LOG_MR,
			       "moving key %"PRIu64":%"PRIu64" to stale (entry %p)\n",
			       entry->key.address, entry->key.length, entry);

			found = rbtFindLeftmost(cache->stale.rb_tree,
						&entry->key,
						util_find_overlapping_addr);
			if (found) {
				/* one or more stale entries would overlap with this
				 * new entry. We need to resolve these collisions by dropping
				 * registrations
				 */
				util_resolve_stale_entry_collision(cache, found, entry);
			} else {
				/* if not found, ... */
				grc = util_insert_entry_into_stale(cache, entry);
			}
		} else {
			/* if retired or not using lazy registration */
			FI_DBG(&core_prov, FI_LOG_MR,
			       "destroying entry, key=%"PRIu64":%"PRIu64" (entry %p)\n",
			       entry->key.address, entry->key.length, entry);

			grc = util_mr_cache_entry_destroy(cache, entry);
		}

		if (OFI_UNLIKELY(grc != FI_SUCCESS))
			FI_INFO(&core_prov, FI_LOG_MR,
				"dereg callback returned %d\n", grc);
	}


	return grc;
}

/**
 * Checks the sanity of cache attributes
 *
 * @param[in]   attr  attributes structure to be checked
 * @return      FI_SUCCESS if the attributes are valid
 *              -FI_EINVAL if the attributes are invalid
 */
static inline int
util_check_mr_cache_attr_sanity(struct util_mr_cache_attr *attr)
{
	/* 0 < attr->hard_reg_limit < attr->soft_reg_limit */
	if (attr->hard_reg_limit > 0 &&
			attr->hard_reg_limit < attr->soft_reg_limit)
		return -FI_EINVAL;

	/* callbacks must be provided */
	if (!attr->reg_callback || !attr->dereg_callback)
		return -FI_EINVAL;

	/* valid otherwise */
	return FI_SUCCESS;
}

int ofi_util_mr_cache_init(struct util_mr_cache **cache,
			   struct util_mr_cache_attr *attr)
{
	struct util_mr_cache_attr *cache_attr =
		&default_mr_cache_attr;
	struct util_mr_cache *cache_p;
	int rc;

	/* if the provider asks us to use their attributes, are they sane? */
	if (attr) {
		if (util_check_mr_cache_attr_sanity(attr) != FI_SUCCESS)
			return -FI_EINVAL;

		cache_attr = attr;
	}

	cache_p = (struct util_mr_cache *)calloc(1, sizeof(*cache_p));
	if (!cache_p)
		return -FI_ENOMEM;

	/* save the attribute values */
	memcpy(&cache_p->attr, cache_attr, sizeof(*cache_attr));

	/* list is used because entries can be removed from the stale list if
	 *   a user might call register on a stale entry's memory region
	 */
	dlist_init(&cache_p->lru_head);

	/* set up inuse tree */
	cache_p->inuse.rb_tree = rbtNew(util_mr_cache_key_comp);
	if (!cache_p->inuse.rb_tree) {
		rc = -FI_ENOMEM;
		goto err_inuse;
	}

	/* if using lazy deregistration, set up stale tree */
	if (cache_p->attr.lazy_deregistration) {
		cache_p->stale.rb_tree = rbtNew(util_mr_cache_key_comp);
		if (!cache_p->stale.rb_tree) {
			rc = -FI_ENOMEM;
			goto err_stale;
		}
	}

	/* initialize the element counts. If we are reinitializing a dead cache,
	 *   destroy will have already set the element counts
	 */
	if (cache_p->state == UTIL_MRC_STATE_UNINITIALIZED) {
		ofi_atomic_initialize32(&cache_p->inuse.elements, 0);
		ofi_atomic_initialize32(&cache_p->stale.elements, 0);
	}

	cache_p->hits = 0;
	cache_p->misses = 0;

	cache_p->state = UTIL_MRC_STATE_READY;

	*cache = cache_p;

	return FI_SUCCESS;

err_stale:
	rbtDelete(cache_p->inuse.rb_tree);
	cache_p->inuse.rb_tree = NULL;
err_inuse:
	free(cache_p);

	return rc;
}

int ofi_util_mr_cache_destroy(struct util_mr_cache *cache)
{
	if (cache->state != UTIL_MRC_STATE_READY)
		return -FI_EINVAL;

	/*
	 * Remove all of the stale entries from the cache
	 */
	ofi_util_mr_cache_flush(cache);

	/*
	 * if there are still elements in the cache after the flush,
	 *   then someone forgot to deregister memory.
	 *   We probably shouldn't destroy the cache at this point.
	 */
	if (ofi_atomic_get32(&cache->inuse.elements) != 0)
		return -FI_EAGAIN;

	/* destroy the tree */
	rbtDelete(cache->inuse.rb_tree);
	cache->inuse.rb_tree = NULL;

	/* stale will been flushed already, so just destroy the tree */
	if (cache->attr.lazy_deregistration) {
		rbtDelete(cache->stale.rb_tree);
		cache->stale.rb_tree = NULL;
	}

	cache->state = UTIL_MRC_STATE_DEAD;
	free(cache);

	return FI_SUCCESS;
}

int util_mr_cache_flush(struct util_mr_cache *cache, int flush_count)
{
	int rc;
	RbtIterator iter;
	struct util_mr_cache_entry *entry;
	int destroyed = 0;

	FI_DBG(&core_prov, FI_LOG_MR, "starting flush"
	       " on memory registration cache\n");

	/* flushes are unnecessary for caches without lazy deregistration */
	if (!cache->attr.lazy_deregistration)
		return FI_SUCCESS;

	while (!dlist_empty(&cache->lru_head)) {
		if (flush_count >= 0 && flush_count == destroyed)
			break;

		rc = util_mr_cache_lru_dequeue(cache, &entry);
		if (OFI_UNLIKELY(rc != FI_SUCCESS)) {
			FI_WARN(&core_prov, FI_LOG_MR,
					"list may be corrupt, no entries from lru pop\n");
			break;
		}

		FI_DBG(&core_prov, FI_LOG_MR, "attempting to flush "
		       "key %"PRIu64":%"PRIu64"\n",
		       entry->key.address, entry->key.length);
		iter = rbtFind(cache->stale.rb_tree, &entry->key);
		if (OFI_UNLIKELY(!iter)) {
			FI_WARN(&core_prov, FI_LOG_MR,
				 "lru entries MUST be present in the cache,"
				 " could not find entry (%p) in stale tree"
				 " %"PRIu64":%"PRIu64"\n",
				 entry, entry->key.address, entry->key.length);
			break;
		}

		rc = rbtErase(cache->stale.rb_tree, iter);
		if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
			FI_WARN(&core_prov, FI_LOG_MR,
				"failed to erase lru entry from stale tree\n");
			break;
		}

		util_mr_cache_entry_destroy(cache, entry);
		entry = NULL;
		++destroyed;
	}

	FI_DBG(&core_prov, FI_LOG_MR, "flushed %i of %i entries from memory "
	       "registration cache\n", destroyed,
	       ofi_atomic_get32(&cache->stale.elements));

	if (destroyed > 0)
		ofi_atomic_sub32(&cache->stale.elements, destroyed);

	return FI_SUCCESS;
}

int ofi_util_mr_cache_flush(struct util_mr_cache *cache)
{

	if (OFI_UNLIKELY(cache->state != UTIL_MRC_STATE_READY))
		return -FI_EINVAL;

	util_mr_cache_flush(cache, cache->attr.hard_reg_limit);

	return FI_SUCCESS;
}

static int util_mr_cache_search_inuse(struct util_mr_cache *cache,
				      uint64_t address,
				      uint64_t length,
				      struct util_mr_cache_entry **entry,
				      struct util_mr_cache_key *key,
				      struct util_fi_reg_context *fi_reg_context)
{
	int ret = FI_SUCCESS, cmp;
	RbtIterator iter;
	struct util_mr_cache_key *found_key, new_key;
	struct util_mr_cache_entry *found_entry;
	uint64_t new_end, found_end;
	DEFINE_LIST(retired_entries);

	if (cache->attr.lazy_deregistration) {
	    /*__clear_notifier_events(cache);
	     TODO*/
	}

	/* first we need to find an entry that overlaps with this one.
	 * care should be taken to find the left most entry that overlaps
	 * with this entry since the entry we are searching for might overlap
	 * many entries and the tree may be left or right balanced
	 * at the head
	 */
	iter = rbtFindLeftmost(cache->inuse.rb_tree, (void *) key,
			util_find_overlapping_addr);
	if (!iter) {
		FI_DBG(&core_prov, FI_LOG_MR,
		       "could not find key in inuse, key=%"PRIu64":%"PRIu64"\n",
		       key->address, key->length);
		return -FI_ENOENT;
	}

	rbtKeyValue(cache->inuse.rb_tree, iter, (void **) &found_key,
			(void **) &found_entry);

	FI_DBG(&core_prov, FI_LOG_MR,
	       "found a key that matches the search criteria, "
	       "found=%"PRIu64":%"PRIu64" key=%"PRIu64":%"PRIu64"\n",
	       found_key->address, found_key->length,
	       key->address, key->length);

	/* if the entry that we've found completely subsumes
	 * the requested entry, just return a reference to
	 * that existing registration
	 */
	if (util_can_subsume(found_key, key)) {
		FI_DBG(&core_prov, FI_LOG_MR,
		       "found an entry that subsumes the request, "
		       "existing=%"PRIu64":%"PRIu64" key=%"PRIu64":%"PRIu64"\n",
		       found_key->address, found_key->length,
		       key->address, key->length);
		*entry = found_entry;
		util_mr_cache_entry_get(cache, found_entry);

		cache->hits++;
		return FI_SUCCESS;
	}

	/* otherwise, iterate from the existing entry until we can no longer
	 * find an entry that overlaps with the new registration and remove
	 * and retire each of those entries.
	 */
	new_key.address = MIN(found_key->address, key->address);
	new_end = key->address + key->length;
	while (iter) {
		rbtKeyValue(cache->inuse.rb_tree, iter, (void **) &found_key,
				(void **) &found_entry);


		cmp = util_find_overlapping_addr(found_key, key);
		FI_DBG(&core_prov, FI_LOG_MR,
		       "candidate: key=%"PRIu64":%"PRIu64" result=%d\n",
		       found_key->address,
		       found_key->length, cmp);
		if (cmp != 0)
			break;

		/* compute new ending address */
		found_end = found_key->address + found_key->length;

		/* mark the entry as retired */
		FI_DBG(&core_prov, FI_LOG_MR,
		       "retiring entry, key=%"PRIu64":%"PRIu64"\n",
		       found_key->address, found_key->length);
		util_entry_set_retired(found_entry);
		dlist_insert_tail(&found_entry->siblings, &retired_entries);

		iter = rbtNext(cache->inuse.rb_tree, iter);
	}
	/* Since our new key might fully overlap every other entry in the tree,
	 * we need to take the maximum of the last entry and the new entry
	 */
	new_key.length = MAX(found_end, new_end) - new_key.address;


	/* remove retired entries from tree */
	FI_DBG(&core_prov, FI_LOG_MR, "removing retired entries from inuse tree\n");
	util_remove_sibling_entries_from_tree(cache,
			&retired_entries, cache->inuse.rb_tree);

	/* create new registration */
	FI_DBG(&core_prov, FI_LOG_MR,
	       "creating a new merged registration, key=%"PRIu64":%"PRIu64"\n",
	       new_key.address, new_key.length);
	ret = util_mr_cache_create_registration(cache,
			new_key.address, new_key.length,
			entry, &new_key, fi_reg_context);
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
		       new_key.address, new_key.length);
		return ret;
	}

	util_entry_set_merged(*entry);

	/* move retired entries to the head of the new entry's child list */
	if (!dlist_empty(&retired_entries)) {
		util_attach_retired_entries_to_registration(cache,
				&retired_entries, *entry);
	}

	cache->misses++;

	return ret;
}

static int util_mr_cache_search_stale(struct util_mr_cache *cache,
				      uint64_t address,
				      uint64_t length,
				      struct util_mr_cache_entry **entry,
				      struct util_mr_cache_key *key,
				      struct util_fi_reg_context *fi_reg_context)
{
	int ret;
	RbtStatus rc;
	RbtIterator iter;
	struct util_mr_cache_key *mr_key;
	struct util_mr_cache_entry *mr_entry, *tmp;

	if (cache->attr.lazy_deregistration) {
	    /*__clear_notifier_events(cache);
		TODO*/
	}

	FI_DBG(&core_prov, FI_LOG_MR,
	       "searching for stale entry, key=%"PRIu64":%"PRIu64"\n",
	       key->address, key->length);

	iter = rbtFindLeftmost(cache->stale.rb_tree, (void *) key,
			       util_find_overlapping_addr);
	if (!iter)
		return -FI_ENOENT;

	rbtKeyValue(cache->stale.rb_tree, iter, (void **) &mr_key,
			(void **) &mr_entry);

	FI_DBG(&core_prov, FI_LOG_MR,
	       "found a matching entry,"
	       " found=%"PRIu64":%"PRIu64
	       " key=%"PRIu64":%"PRIu64"\n",
	       mr_key->address, mr_key->length,
	       key->address, key->length);


	/* if the entry that we've found completely subsumes
	 * the requested entry, just return a reference to
	 * that existing registration
	 */
	if (util_can_subsume(mr_key, key)) {
		ret = util_mr_cache_search_inuse(cache, address, length,
				&tmp, mr_key, fi_reg_context);
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
			       mr_key->address, mr_key->length);

			rc = rbtErase(cache->stale.rb_tree, iter);
			if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
				FI_WARN(&core_prov, FI_LOG_MR,
						"failed to erase entry from stale tree\n");
			} else {
				if (util_mr_cache_lru_remove(cache, mr_entry)
				    == FI_SUCCESS) {
					ofi_atomic_dec32(&cache->stale.elements);
				} else {
					FI_WARN(&core_prov, FI_LOG_MR, "Failed to remove"
						  " entry (%p) from lru list\n",
						  mr_entry);
				}
				util_mr_cache_entry_destroy(cache, mr_entry);
			}

			*entry = tmp;
		} else {
			FI_DBG(&core_prov, FI_LOG_MR,
			       "removing entry (%p) from stale and"
			       " migrating to inuse, key=%"PRIu64":%"PRIu64"\n",
			       mr_entry, mr_key->address, mr_key->length);
			rc = rbtErase(cache->stale.rb_tree, iter);
			if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
			    FI_WARN(&core_prov, FI_LOG_MR,
					   "failed to erase entry (%p) from "
					   " stale tree\n", mr_entry);
			}

			if (util_mr_cache_lru_remove(cache, mr_entry) != FI_SUCCESS) {
				FI_WARN(&core_prov, FI_LOG_MR, "Failed to remove"
					" entry (%p) from lru list\n",
					mr_entry);
			}

			ofi_atomic_dec32(&cache->stale.elements);

			/* if we made it to this point, there weren't
			 * any entries in the inuse tree that would
			 * have overlapped with this entry
			 */
			rc = rbtInsert(cache->inuse.rb_tree,
					&mr_entry->key, mr_entry);
			if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
				FI_WARN(&core_prov, FI_LOG_MR,
					"failed to insert entry into"
					"inuse tree\n");
			}

			ofi_atomic_set32(&mr_entry->ref_cnt, 1);
			ofi_atomic_inc32(&cache->inuse.elements);

			*entry = mr_entry;
		}

		return FI_SUCCESS;
	}

	FI_DBG(&core_prov, FI_LOG_MR,
	       "could not use matching entry, "
	       "found=%"PRIu64":%"PRIu64"\n",
	       mr_key->address, mr_key->length);

	return -FI_ENOENT;
}

static int util_mr_cache_create_registration(struct util_mr_cache *cache,
					     uint64_t address, uint64_t length,
					     struct util_mr_cache_entry **entry,
					     struct util_mr_cache_key *key,
					     struct util_fi_reg_context *fi_reg_context)
{
	int rc;
	struct util_mr_cache_entry *current_entry;
	void *handle;

	/* if we made it here, we didn't find the entry at all */
	current_entry = calloc(1, sizeof(*current_entry) + cache->attr.elem_size);
	if (!current_entry)
		return -FI_ENOMEM;

	handle = (void *)current_entry->mr;

	dlist_init(&current_entry->lru_entry);
	dlist_init(&current_entry->children);
	dlist_init(&current_entry->siblings);

	handle = cache->attr.reg_callback(handle, (void *)address, length,
			fi_reg_context, cache->attr.reg_context);
	if (OFI_UNLIKELY(!handle)) {
		FI_INFO(&core_prov, FI_LOG_MR,
			  "failed to register memory with callback\n");
		goto err;
	}

	util_entry_reset_state(current_entry);

	/* set up the entry's key */
	current_entry->key.address = address;
	current_entry->key.length = length;

	/*rc = __notifier_monitor(cache, current_entry);
	if (OFI_UNLIKELY(rc != FI_SUCCESS)) {
		GNIX_INFO(FI_LOG_MR,
			  "failed to monitor memory with notifier\n");
		goto err_dereg;
	} MONITOR */

	rc = rbtInsert(cache->inuse.rb_tree, &current_entry->key,
			current_entry);
	if (OFI_UNLIKELY(rc != RBT_STATUS_OK)) {
		FI_WARN(&core_prov, FI_LOG_MR, "failed to insert registration "
				"into cache, ret=%i\n", rc);

		goto err_dereg;
	}

	FI_DBG(&core_prov, FI_LOG_MR,
	       "inserted key %"PRIu64":%"PRIu64" into inuse (entry is %p)\n",
	       current_entry->key.address, current_entry->key.length,
	       current_entry);

	ofi_atomic_inc32(&cache->inuse.elements);
	ofi_atomic_initialize32(&current_entry->ref_cnt, 1);

	*entry = current_entry;

	return FI_SUCCESS;

err_dereg:
	rc = cache->attr.dereg_callback(current_entry->mr,
					cache->attr.dereg_context);
	if (OFI_UNLIKELY(rc)) {
	    FI_INFO(&core_prov, FI_LOG_MR,
			  "failed to deregister memory with "
			  "callback, ret=%d\n", rc);
	}
err:
	free(current_entry);
	return -FI_ENOMEM;
}


/**
 * Function to register memory with the cache
 *
 * @param[in] cache           gnix memory registration cache pointer
 * @param[in] mr              gnix memory region descriptor pointer
 * @param[in] address         base address of the memory region to be
 *                            registered
 * @param[in] length          length of the memory region to be registered
 * @param[in] fi_reg_context  fi_reg_mr API call parameters
 * @param[in,out] mem_hndl    gni memory handle pointer to written to and
 *                            returned
 */
int ofi_util_mr_cache_register(struct util_mr_cache *cache,
			   uint64_t address, uint64_t length,
			   struct util_fi_reg_context *fi_reg_context,
			   void **handle)
{
	int ret;
	struct util_mr_cache_key key = {
		.address = address,
		.length = length,
	};
	struct util_mr_cache_entry *entry;

	/* fastpath inuse */
	ret = util_mr_cache_search_inuse(cache, address, length,
			&entry, &key, fi_reg_context);
	if (ret == FI_SUCCESS)
		goto success;

	/* if we shouldn't introduce any new elements, return -FI_ENOSPC */
	if (OFI_UNLIKELY(cache->attr.hard_reg_limit > 0 &&
			 (ofi_atomic_get32(&cache->inuse.elements) >=
			  cache->attr.hard_reg_limit))) {
		ret = -FI_ENOSPC;
		goto err;
	}

	if (cache->attr.lazy_deregistration) {
	    /*__clear_notifier_events(cache);*/

		/* if lazy deregistration is in use, we can check the
		 *   stale tree
		 */
		ret = util_mr_cache_search_stale(cache, address, length,
				&entry, &key, fi_reg_context);
		if (ret == FI_SUCCESS) {
			cache->hits++;
			goto success;
		}
	}

	/* If the cache is full, then flush one of the stale entries to make
	 *   room for the new entry. This works because we check above to see if
	 *   the number of inuse entries exceeds the hard reg limit
	 */
	if ((ofi_atomic_get32(&cache->inuse.elements) +
		ofi_atomic_get32(&cache->stale.elements))
			== cache->attr.hard_reg_limit)
		util_mr_cache_flush(cache, 1);

	ret = util_mr_cache_create_registration(cache, address, length,
			&entry, &key, fi_reg_context);
	if (ret) {
		goto err;
	}

	cache->misses++;

success:
	util_entry_set_state(entry, UTIL_CES_INUSE);
	*handle = (void *) entry->mr;

	return FI_SUCCESS;

err:
	return ret;
}

/**
 * Function to deregister memory in the cache
 *
 * @param[in]  mr     gnix memory registration descriptor pointer
 *
 * @return     FI_SUCCESS on success
 *             -FI_ENOENT if there isn't an active memory registration
 *               associated with the mr
 *             return codes associated with dereg callback
 */
int ofi_util_mr_cache_deregister(struct util_mr_cache *cache,
			     void *handle)
{
	struct util_mr_cache_entry *entry;
	int grc;

	/* check to see if we can find the entry so that we can drop the
	 *   held reference
	 */

	entry = container_of(handle, struct util_mr_cache_entry, mr);
	if (util_entry_get_state(entry) != UTIL_CES_INUSE) {
		FI_INFO(&core_prov, FI_LOG_MR,
			"entry (%p) in incorrect state (%llu)\n",
			entry, entry->state);
		return -FI_EINVAL;
	}

	FI_DBG(&core_prov, FI_LOG_MR, "entry found, entry=%p refs=%d\n",
		   entry, ofi_atomic_get32(&entry->ref_cnt));

	grc = util_mr_cache_entry_put(cache, entry);

	/* Since we check this on each deregistration, the amount of elements
	 * over the limit should always be 1
	 */
	if (ofi_atomic_get32(&cache->stale.elements) > cache->attr.hard_stale_limit)
		util_mr_cache_flush(cache, 1);

	return grc;
}
