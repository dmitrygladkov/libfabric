/*
 * Copyright (c) 2015-2017 Intel Corporation. All rights reserved.
 * Copyright (c) 2017, Cisco Systems, Inc. All rights reserved.
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

#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <inttypes.h>

#if HAVE_GETIFADDRS
#include <net/if.h>
#include <ifaddrs.h>
#endif

#include <ofi_util.h>


enum {
	UTIL_NO_ENTRY = -1,
	UTIL_DEFAULT_AV_SIZE = 1024,
};

static int ofi_cmap_move_handle_to_peer_list(struct util_cmap *cmap, fi_addr_t fi_addr);

static int fi_get_src_sockaddr(const struct sockaddr *dest_addr, size_t dest_addrlen,
			       struct sockaddr **src_addr, size_t *src_addrlen)
{
	socklen_t len; /* needed for OS compatability */
	int sock, ret;

	sock = socket(dest_addr->sa_family, SOCK_DGRAM, 0);
	if (sock < 0)
		return -errno;

	ret = connect(sock, dest_addr, dest_addrlen);
	if (ret)
		goto out;

	*src_addr = calloc(dest_addrlen, 1);
	if (!*src_addr) {
		ret = -FI_ENOMEM;
		goto out;
	}

	len = (socklen_t) dest_addrlen;
	ret = getsockname(sock, *src_addr, &len);
	if (ret) {
		ret = -errno;
		goto out;
	}
	*src_addrlen = len;

	switch ((*src_addr)->sa_family) {
	case AF_INET:
		((struct sockaddr_in *) (*src_addr))->sin_port = 0;
		break;
	case AF_INET6:
		((struct sockaddr_in6 *) (*src_addr))->sin6_port = 0;
		break;
	default:
		ret = -FI_ENOSYS;
		break;
	}

out:
	ofi_close_socket(sock);
	return ret;

}

void ofi_getnodename(uint16_t sa_family, char *buf, int buflen)
{
	int ret;
	struct addrinfo ai, *rai = NULL;
	struct ifaddrs *ifaddrs, *ifa;

	assert(buf && buflen > 0);
	ret = gethostname(buf, buflen);
	buf[buflen - 1] = '\0';
	if (ret == 0) {
		memset(&ai, 0, sizeof(ai));
		ai.ai_family = sa_family  ? sa_family : AF_INET;
		ret = getaddrinfo(buf, NULL, &ai, &rai);
		if (!ret) {
			freeaddrinfo(rai);
			return;
		}
	}

#if HAVE_GETIFADDRS
	ret = ofi_getifaddrs(&ifaddrs);
	if (!ret) {
		for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP))
				continue;

			if (sa_family) {
				if (ifa->ifa_addr->sa_family != sa_family)
					continue;
			} else if ((ifa->ifa_addr->sa_family != AF_INET) &&
				   (ifa->ifa_addr->sa_family != AF_INET6)) {
				continue;
			}

			ret = getnameinfo(ifa->ifa_addr, ofi_sizeofaddr(ifa->ifa_addr),
				  	  buf, buflen, NULL, 0, NI_NUMERICHOST);
			buf[buflen - 1] = '\0';
			if (ret == 0) {
				freeifaddrs(ifaddrs);
				return;
			}
		}
		freeifaddrs(ifaddrs);
	}
#endif
	/* no reasonable address found, use ipv4 loopback */
	strncpy(buf, "127.0.0.1", buflen);
	buf[buflen - 1] = '\0';
}

int ofi_get_src_addr(uint32_t addr_format,
		    const void *dest_addr, size_t dest_addrlen,
		    void **src_addr, size_t *src_addrlen)
{
	switch (addr_format) {
	case FI_SOCKADDR:
	case FI_SOCKADDR_IN:
	case FI_SOCKADDR_IN6:
		return fi_get_src_sockaddr(dest_addr, dest_addrlen,
					   (struct sockaddr **) src_addr,
					   src_addrlen);
	default:
		return -FI_ENOSYS;
	}
}

static int fi_get_sockaddr(int sa_family, uint64_t flags,
			   const char *node, const char *service,
			   struct sockaddr **addr, size_t *addrlen)
{
	struct addrinfo hints, *ai;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = sa_family;
	hints.ai_socktype = SOCK_STREAM;
	if (flags & FI_SOURCE)
		hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(node, service, &hints, &ai);
	if (ret)
		return -FI_ENODATA;

	*addr = mem_dup(ai->ai_addr, ai->ai_addrlen);
	if (!*addr) {
		ret = -FI_ENOMEM;
		goto out;
	}

	*addrlen = ai->ai_addrlen;
out:
	freeaddrinfo(ai);
	return ret;
}

void ofi_get_str_addr(const char *node, const char *service,
		      char **addr, size_t *addrlen)
{
	if (!node || !strstr(node, "://"))
		return;

	*addr = strdup(node);
	*addrlen = strlen(node) + 1;
}

int ofi_get_addr(uint32_t addr_format, uint64_t flags,
		const char *node, const char *service,
		void **addr, size_t *addrlen)
{
	switch (addr_format) {
	case FI_SOCKADDR:
		return fi_get_sockaddr(0, flags, node, service,
				       (struct sockaddr **) addr, addrlen);
	case FI_SOCKADDR_IN:
		return fi_get_sockaddr(AF_INET, flags, node, service,
				       (struct sockaddr **) addr, addrlen);
	case FI_SOCKADDR_IN6:
		return fi_get_sockaddr(AF_INET6, flags, node, service,
				       (struct sockaddr **) addr, addrlen);
	case FI_ADDR_STR:
		ofi_get_str_addr(node, service, (char **) addr, addrlen);
		return 0;
	default:
		return -FI_ENOSYS;
	}
}

static int fi_verify_av_insert(struct util_av *av, uint64_t flags)
{
	if ((av->flags & FI_EVENT) && !av->eq) {
		FI_WARN(av->prov, FI_LOG_AV, "no EQ bound to AV\n");
		return -FI_ENOEQ;
	}

	if (flags & ~(FI_MORE)) {
		FI_WARN(av->prov, FI_LOG_AV, "unsupported flags\n");
		return -FI_ENOEQ;
	}

	return 0;
}

/*
 * Must hold AV lock
 */
int ofi_av_insert_addr(struct util_av *av, const void *addr, fi_addr_t *fi_addr)
{
	struct dlist_entry *av_entry;
	struct util_ep *ep;
	int ret;
	struct util_av_entry *entry = NULL;

	if (av->flags & OFI_AV_HASH) {
		HASH_FIND(hh, av->av_hash.hash, &addr, av->addrlen, entry);
		if (entry) {
			*fi_addr = util_get_buf_index(av->av_entry_pool, entry);
		} else {
			entry = util_buf_alloc(av->av_entry_pool);
			if (!entry)
				return -FI_ENOMEM;
			*fi_addr = util_get_buf_index(av->av_entry_pool, entry);
			memcpy(entry->addr, addr, av->addrlen);
			ofi_atomic_initialize32(&entry->use_cnt, 0);
			HASH_ADD(hh, av->av_hash.hash, addr, av->addrlen, entry);
		}
		ofi_atomic_inc32(&entry->use_cnt);
	}

	if (!entry) {
		entry = util_buf_alloc(av->av_entry_pool);
		if (!entry)
			return -FI_ENOMEM;
		*fi_addr = util_get_buf_index(av->av_entry_pool, entry);
		memcpy(entry->addr, addr, av->addrlen);
		ofi_atomic_initialize32(&entry->use_cnt, 1);
	}

	dlist_foreach(&av->ep_list, av_entry) {
		ep = container_of(av_entry, struct util_ep, av_entry);
		if (ep->cmap) {
			ret = ofi_cmap_update(ep->cmap, addr, *fi_addr);
			if (OFI_UNLIKELY(ret)) {
				int retv;
				FI_WARN(av->prov, FI_LOG_AV,
					"Unable to update CM for OFI endpoints\n");
				retv = ofi_av_remove_addr(av, *fi_addr);
				if (retv)
					FI_WARN(av->prov, FI_LOG_AV,
						"Failed to remove addr from AV during error handling\n");
				return ret;
			}
		}
	}
	return 0;
}

/*
 * Must hold AV lock
 */
int ofi_av_remove_addr(struct util_av *av, fi_addr_t fi_addr)
{
	struct util_ep *ep;
	int ret = 0;
	struct util_av_entry *av_entry =
		util_buf_get_by_index(av->av_entry_pool, fi_addr);
	if (!av_entry)
		return ret;

	/* This should stay at top */
	dlist_foreach_container(&av->ep_list, struct util_ep,
				ep, av_entry) {
		if (ep->cmap) {
			if (ep->cmap->av_handle_table[fi_addr]) {
				/* TODO this is not optimal. Replace this with something
				 * more deterministic: delete handle if we know that peer
				 * isn't actively communicating with us */
				ret = ofi_cmap_move_handle_to_peer_list(ep->cmap, fi_addr);
				if (ret) {
					FI_WARN(av->prov, FI_LOG_DOMAIN, "Unable to move"
						" handle to peer list. Deleting it.\n");
					ofi_cmap_del_handle(ep->cmap->av_handle_table[fi_addr]);
					return ret;
				}
			}
		}
	}

	util_buf_release(av->av_entry_pool, av_entry);

	return ret;
}

fi_addr_t ofi_av_lookup_fi_addr(struct util_av *av, const void *addr)
{
	fi_addr_t fi_addr = FI_ADDR_NOTAVAIL;
	struct util_av_entry *entry;

	fastlock_acquire(&av->lock);
	HASH_FIND(hh, av->av_hash.hash, &addr, av->addrlen, entry);
	if (entry) {
		fi_addr = util_get_buf_index(av->av_entry_pool, entry);
	}
	fastlock_release(&av->lock);

	return fi_addr;
}

int ofi_av_bind(struct fid *av_fid, struct fid *eq_fid, uint64_t flags)
{
	struct util_av *av;
	struct util_eq *eq;

	av = container_of(av_fid, struct util_av, av_fid.fid);
	if (eq_fid->fclass != FI_CLASS_EQ) {
		FI_WARN(av->prov, FI_LOG_AV, "invalid fid class\n");
		return -FI_EINVAL;
	}

	if (flags) {
		FI_WARN(av->prov, FI_LOG_AV, "invalid flags\n");
		return -FI_EINVAL;
	}

	eq = container_of(eq_fid, struct util_eq, eq_fid.fid);
	av->eq = eq;
	ofi_atomic_inc32(&eq->ref);
	return 0;
}

static void util_av_close(struct util_av *av)
{
	util_buf_pool_destroy(av->av_entry_pool);
}

int ofi_av_close_lightweight(struct util_av *av)
{
	if (ofi_atomic_get32(&av->ref)) {
		FI_WARN(av->prov, FI_LOG_AV, "AV is busy\n");
		return -FI_EBUSY;
	}

	if (av->eq)
		ofi_atomic_dec32(&av->eq->ref);

	ofi_atomic_dec32(&av->domain->ref);
	fastlock_destroy(&av->lock);

	return 0;
}

int ofi_av_close(struct util_av *av)
{
	int ret = ofi_av_close_lightweight(av);
	if (ret)
		return ret;
	util_av_close(av);
	return 0;
}

static int util_verify_av_util_attr(struct util_domain *domain,
				    const struct util_av_attr *util_attr)
{
	if (util_attr->flags & ~(OFI_AV_HASH)) {
		FI_WARN(domain->prov, FI_LOG_AV, "invalid internal flags\n");
		return -FI_EINVAL;
	}

	if (util_attr->addrlen < sizeof(int)) {
		FI_WARN(domain->prov, FI_LOG_AV, "unsupported address size\n");
		return -FI_ENOSYS;
	}

	return 0;
}

static int util_av_init(struct util_av *av, const struct fi_av_attr *attr,
			const struct util_av_attr *util_attr)
{
	int ret = 0;
	size_t max_count;
	struct util_buf_attr pool_attr = {
		.size		= util_attr->addrlen +
				  sizeof(struct util_av_entry),
		.alignment	= 16,
		.max_cnt	= 0,
		.track_used	= 0,
		.use_ftr	= 1,
	};

	ret = util_verify_av_util_attr(av->domain, util_attr);
	if (ret)
		return ret;

	if (attr->count) {
		max_count = attr->count;
	} else {
		if (fi_param_get_size_t(NULL, "universe_size", &max_count))
			max_count = UTIL_DEFAULT_AV_SIZE;
	}

	av->count = max_count ? max_count : UTIL_DEFAULT_AV_SIZE;
	av->count = roundup_power_of_two(av->count);
	av->addrlen = util_attr->addrlen;
	av->flags = util_attr->flags | attr->flags;

	FI_INFO(av->prov, FI_LOG_AV, "AV size %zu\n", av->count);

	pool_attr.chunk_cnt = av->count;
	ret = util_buf_pool_create_attr(&pool_attr, &av->av_entry_pool);
	if (ret) {
		return ret;
	}

	/* TODO: Handle FI_READ */
	/* TODO: Handle mmap - shared AV */

	if (util_attr->flags & OFI_AV_HASH) {
		av->av_hash.av = av;
		av->av_hash.hash = NULL;
	}

	return ret;
}

static int util_verify_av_attr(struct util_domain *domain,
			       const struct fi_av_attr *attr)
{
	switch (attr->type) {
	case FI_AV_MAP:
	case FI_AV_TABLE:
		if ((domain->av_type != FI_AV_UNSPEC) &&
		    (attr->type != domain->av_type)) {
			FI_INFO(domain->prov, FI_LOG_AV, "Invalid AV type\n");
		   	return -FI_EINVAL;
		}
		break;
	default:
		FI_WARN(domain->prov, FI_LOG_AV, "invalid av type\n");
		return -FI_EINVAL;
	}

	if (attr->name) {
		FI_WARN(domain->prov, FI_LOG_AV, "Shared AV is unsupported\n");
		return -FI_ENOSYS;
	}

	if (attr->flags & ~(FI_EVENT | FI_READ | FI_SYMMETRIC)) {
		FI_WARN(domain->prov, FI_LOG_AV, "invalid flags\n");
		return -FI_EINVAL;
	}

	return 0;
}

int ofi_av_init_lightweight(struct util_domain *domain, const struct fi_av_attr *attr,
			    struct util_av *av, void *context)
{
	int ret;

	ret = util_verify_av_attr(domain, attr);
	if (ret)
		return ret;

	av->prov = domain->prov;
	ofi_atomic_initialize32(&av->ref, 0);
	fastlock_init(&av->lock);
	av->av_fid.fid.fclass = FI_CLASS_AV;
	/*
	 * ops set by provider
	 * av->av_fid.fid.ops = &prov_av_fi_ops;
	 * av->av_fid.ops = &prov_av_ops;
	 */
	av->context = context;
	av->domain = domain;
	dlist_init(&av->ep_list);
	ofi_atomic_inc32(&domain->ref);
	return 0;
}

int ofi_av_init(struct util_domain *domain, const struct fi_av_attr *attr,
		const struct util_av_attr *util_attr,
		struct util_av *av, void *context)
{
	int ret = ofi_av_init_lightweight(domain, attr, av, context);
	if (ret)
		return ret;

	ret = util_av_init(av, attr, util_attr);
	if (ret)
		return ret;
	return ret;
}


/*************************************************************************
 *
 * AV for IP addressing
 *
 *************************************************************************/

fi_addr_t ip_av_get_fi_addr(struct util_av *av, const void *addr)
{
	return ofi_av_lookup_fi_addr(av, addr);
}

void ofi_av_write_event(struct util_av *av, uint64_t data,
			int err, void *context)
{
	struct fi_eq_err_entry entry = { 0 };
	size_t size;
	ssize_t ret;
	uint64_t flags;

	entry.fid = &av->av_fid.fid;
	entry.context = context;
	entry.data = data;

	if (err) {
		FI_INFO(av->prov, FI_LOG_AV, "writing error entry to EQ\n");
		entry.err = err;
		size = sizeof(struct fi_eq_err_entry);
		flags = UTIL_FLAG_ERROR;
	} else {
		FI_DBG(av->prov, FI_LOG_AV, "writing entry to EQ\n");
		size = sizeof(struct fi_eq_entry);
		flags = 0;
	}

	ret = fi_eq_write(&av->eq->eq_fid, FI_AV_COMPLETE, &entry,
			  size, flags);
	if (ret != size)
		FI_WARN(av->prov, FI_LOG_AV, "error writing to EQ\n");
}

static int ip_av_valid_addr(struct util_av *av, const void *addr)
{
	const struct sockaddr_in *sin = addr;
	const struct sockaddr_in6 *sin6 = addr;

	switch (sin->sin_family) {
	case AF_INET:
		return sin->sin_port && sin->sin_addr.s_addr;
	case AF_INET6:
		return sin6->sin6_port &&
		      memcmp(&in6addr_any, &sin6->sin6_addr, sizeof(in6addr_any));
	default:
		return 0;
	}
}

static int ip_av_insert_addr(struct util_av *av, const void *addr,
			     fi_addr_t *fi_addr, void *context)
{
	int ret;
	fi_addr_t fi_addr_ret;

	if (ip_av_valid_addr(av, addr)) {
		fastlock_acquire(&av->lock);
		ret = ofi_av_insert_addr(av, addr, &fi_addr_ret);
		fastlock_release(&av->lock);
	} else {
		ret = -FI_EADDRNOTAVAIL;
		FI_WARN(av->prov, FI_LOG_AV, "invalid address\n");
	}

	if (fi_addr)
		*fi_addr = !ret ? fi_addr_ret : FI_ADDR_NOTAVAIL;

	ofi_straddr_dbg(av->prov, FI_LOG_AV, "av_insert addr", addr);
	if (fi_addr)
		FI_DBG(av->prov, FI_LOG_AV, "av_insert fi_addr: %" PRIu64 "\n",
		       *fi_addr);

	return ret;
}

static int ip_av_insert(struct fid_av *av_fid, const void *addr, size_t count,
			fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct util_av *av;
	int ret, success_cnt = 0;
	size_t i;
	size_t addrlen;

	av = container_of(av_fid, struct util_av, av_fid);
	ret = fi_verify_av_insert(av, flags);
	if (ret)
		return ret;

	addrlen = ((struct sockaddr *) addr)->sa_family == AF_INET ?
		  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	FI_DBG(av->prov, FI_LOG_AV, "inserting %zu addresses\n", count);
	for (i = 0; i < count; i++) {
		ret = ip_av_insert_addr(av, (const char *) addr + i * addrlen,
					fi_addr ? &fi_addr[i] : NULL, context);
		if (!ret)
			success_cnt++;
		else if (av->eq)
			ofi_av_write_event(av, i, -ret, context);
	}

	FI_DBG(av->prov, FI_LOG_AV, "%d addresses successful\n", success_cnt);
	if (av->eq) {
		ofi_av_write_event(av, success_cnt, 0, context);
		ret = 0;
	} else {
		ret = success_cnt;
	}
	return ret;
}

static int ip_av_insert_svc(struct util_av *av, const char *node,
			    const char *service, fi_addr_t *fi_addr,
			    void *context)
{
	struct addrinfo hints, *ai;
	int ret;

	FI_INFO(av->prov, FI_LOG_AV, "inserting %s-%s\n", node, service);

	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_DGRAM;
	switch (av->domain->addr_format) {
	case FI_SOCKADDR_IN:
		hints.ai_family = AF_INET;
		break;
	case FI_SOCKADDR_IN6:
		hints.ai_family = AF_INET6;
		break;
	default:
		break;
	}

	ret = getaddrinfo(node, service, &hints, &ai);
	if (ret)
		return ret;

	ret = ip_av_insert_addr(av, ai->ai_addr, fi_addr, context);
	freeaddrinfo(ai);
	return ret;
}

static int ip_av_insertsvc(struct fid_av *av, const char *node,
			   const char *service, fi_addr_t *fi_addr,
			   uint64_t flags, void *context)
{
	return fi_av_insertsym(av, node, 1, service, 1, fi_addr, flags, context);
}

static int ip_av_insert_ip4sym(struct util_av *av,
			       struct in_addr ip, size_t ipcnt,
			       uint16_t port, size_t portcnt,
			       fi_addr_t *fi_addr, void *context)
{
	struct sockaddr_in sin;
	int fi, ret, success_cnt = 0;
	size_t i, p;

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;

	for (i = 0, fi = 0; i < ipcnt; i++) {
		/* TODO: should we skip addresses x.x.x.0 and x.x.x.255? */
		sin.sin_addr.s_addr = htonl(ntohl(ip.s_addr) + i);

		for (p = 0; p < portcnt; p++, fi++) {
			sin.sin_port = htons(port + p);
			ret = ip_av_insert_addr(av, &sin, fi_addr ?
						&fi_addr[fi] : NULL, context);
			if (!ret)
				success_cnt++;
			else if (av->eq)
				ofi_av_write_event(av, fi, -ret, context);
		}
	}

	return success_cnt;
}

static int ip_av_insert_ip6sym(struct util_av *av,
			       struct in6_addr ip, size_t ipcnt,
			       uint16_t port, size_t portcnt,
			       fi_addr_t *fi_addr, void *context)
{
	struct sockaddr_in6 sin6;
	int j, fi, ret, success_cnt = 0;
	size_t i, p;

	memset(&sin6, 0, sizeof sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = ip;

	for (i = 0, fi = 0; i < ipcnt; i++) {
		for (p = 0; p < portcnt; p++, fi++) {
			sin6.sin6_port = htons(port + p);
			ret = ip_av_insert_addr(av, &sin6, fi_addr ?
						&fi_addr[fi] : NULL, context);
			if (!ret)
				success_cnt++;
			else if (av->eq)
				ofi_av_write_event(av, fi, -ret, context);
		}

		/* TODO: should we skip addresses x::0 and x::255? */
		for (j = 15; j >= 0; j--) {
			if (++sin6.sin6_addr.s6_addr[j] < 255)
				break;
		}
	}

	return success_cnt;
}

static int ip_av_insert_nodesym(struct util_av *av,
				const char *node, size_t nodecnt,
				const char *service, size_t svccnt,
				fi_addr_t *fi_addr, void *context)
{
	char name[FI_NAME_MAX];
	char svc[FI_NAME_MAX];
	size_t name_len, n, s;
	int fi, ret, name_index, svc_index, success_cnt = 0;

	for (name_len = strlen(node); isdigit(node[name_len - 1]); )
		name_len--;

	memcpy(name, node, name_len);
	name_index = atoi(node + name_len);
	svc_index = atoi(service);

	for (n = 0, fi = 0; n < nodecnt; n++) {
		if (nodecnt == 1) {
			strncpy(name, node, sizeof(name) - 1);
			name[FI_NAME_MAX - 1] = '\0';
		} else {
			snprintf(name + name_len, sizeof(name) - name_len - 1,
				 "%zu", name_index + n);
		}

		for (s = 0; s < svccnt; s++, fi++) {
			if (svccnt == 1) {
				strncpy(svc, service, sizeof(svc) - 1);
				svc[FI_NAME_MAX - 1] = '\0';
			} else {
				snprintf(svc, sizeof(svc) - 1,
					 "%zu", svc_index + s);
			}

			ret = ip_av_insert_svc(av, name, svc, fi_addr ?
					       &fi_addr[fi] : NULL, context);
			if (!ret)
				success_cnt++;
			else if (av->eq)
				ofi_av_write_event(av, fi, -ret, context);
		}
	}

	return success_cnt;
}

static int ip_av_insertsym(struct fid_av *av_fid, const char *node, size_t nodecnt,
			   const char *service, size_t svccnt, fi_addr_t *fi_addr,
			   uint64_t flags, void *context)
{
	struct util_av *av;
	struct in6_addr ip6;
	struct in_addr ip4;
	int ret;

	av = container_of(av_fid, struct util_av, av_fid);
	ret = fi_verify_av_insert(av, flags);
	if (ret)
		return ret;

	if (strlen(node) >= FI_NAME_MAX || strlen(service) >= FI_NAME_MAX) {
		FI_WARN(av->prov, FI_LOG_AV,
			"node or service name is too long\n");
		return -FI_ENOSYS;
	}

	ret = inet_pton(AF_INET, node, &ip4);
	if (ret == 1) {
		FI_INFO(av->prov, FI_LOG_AV, "insert symmetric IPv4\n");
		ret = ip_av_insert_ip4sym(av, ip4, nodecnt,
					  (uint16_t) strtol(service, NULL, 0),
					  svccnt, fi_addr, context);
		goto out;
	}

	ret = inet_pton(AF_INET6, node, &ip6);
	if (ret == 1) {
		FI_INFO(av->prov, FI_LOG_AV, "insert symmetric IPv6\n");
		ret = ip_av_insert_ip6sym(av, ip6, nodecnt,
					  (uint16_t) strtol(service, NULL, 0),
					  svccnt, fi_addr, context);
		goto out;
	}

	FI_INFO(av->prov, FI_LOG_AV, "insert symmetric host names\n");
	ret = ip_av_insert_nodesym(av, node, nodecnt, service, svccnt,
				  fi_addr, context);

out:
	if (av->eq) {
		ofi_av_write_event(av, ret, 0, context);
		ret = 0;
	}
	return ret;
}

static int ip_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr,
			size_t count, uint64_t flags)
{
	struct util_av *av;
	int i, ret;

	av = container_of(av_fid, struct util_av, av_fid);
	if (flags) {
		FI_WARN(av->prov, FI_LOG_AV, "invalid flags\n");
		return -FI_EINVAL;
	}

	/*
	 * It's more efficient to remove addresses from high to low index.
	 * We assume that addresses are removed in the same order that they were
	 * added -- i.e. fi_addr passed in here was also passed into insert.
	 * Thus, we walk through the array backwards.
	 */
	for (i = count - 1; i >= 0; i--) {
		fastlock_acquire(&av->lock);
		ret = ofi_av_remove_addr(av, fi_addr[i]);
		fastlock_release(&av->lock);
		if (ret) {
			FI_WARN(av->prov, FI_LOG_AV,
				"removal of fi_addr %"PRIu64" failed\n",
				fi_addr[i]);
		}
	}
	return 0;
}

static int ip_av_lookup(struct fid_av *av_fid, fi_addr_t fi_addr, void *addr,
			size_t *addrlen)
{
	struct util_av *av =
		container_of(av_fid, struct util_av, av_fid);
	struct util_av_entry *av_entry =
		util_buf_get_by_index(av->av_entry_pool, fi_addr);

	memcpy(addr, av_entry->addr, MIN(*addrlen, av->addrlen));
	*addrlen = av->addrlen;
	return 0;
}

static const char *ip_av_straddr(struct fid_av *av, const void *addr, char *buf,
				 size_t *len)
{
	return ofi_straddr(buf, len, FI_SOCKADDR, addr);
}

static struct fi_ops_av ip_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = ip_av_insert,
	.insertsvc = ip_av_insertsvc,
	.insertsym = ip_av_insertsym,
	.remove = ip_av_remove,
	.lookup = ip_av_lookup,
	.straddr = ip_av_straddr,
};

static int ip_av_close(struct fid *av_fid)
{
	struct util_av *av;
	int ret;

	av = container_of(av_fid, struct util_av, av_fid.fid);
	ret = ofi_av_close(av);
	if (ret)
		return ret;
	free(av);
	return 0;
}

static struct fi_ops ip_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = ip_av_close,
	.bind = ofi_av_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

int ip_av_create_flags(struct fid_domain *domain_fid, struct fi_av_attr *attr,
		       struct fid_av **av, void *context, int flags)
{
	struct util_domain *domain;
	struct util_av_attr util_attr;
	struct util_av *util_av;
	int ret;

	domain = container_of(domain_fid, struct util_domain, domain_fid);
	if (domain->addr_format == FI_SOCKADDR_IN)
		util_attr.addrlen = sizeof(struct sockaddr_in);
	else
		util_attr.addrlen = sizeof(struct sockaddr_in6);

	util_attr.overhead = attr->count >> 1;
	util_attr.flags = flags;

	if (attr->type == FI_AV_UNSPEC)
		attr->type = FI_AV_MAP;

	util_av = calloc(1, sizeof(*util_av));
	if (!util_av)
		return -FI_ENOMEM;

	ret = ofi_av_init(domain, attr, &util_attr, util_av, context);
	if (ret) {
		free(util_av);
		return ret;
	}

	*av = &util_av->av_fid;
	(*av)->fid.ops = &ip_av_fi_ops;
	(*av)->ops = &ip_av_ops;
	return 0;
}

int ip_av_create(struct fid_domain *domain_fid, struct fi_av_attr *attr,
		 struct fid_av **av, void *context)
{
	struct util_domain *domain = container_of(domain_fid, struct util_domain,
						  domain_fid);

	return ip_av_create_flags(domain_fid, attr, av, context,
				  (domain->info_domain_caps & FI_SOURCE) ?
				  OFI_AV_HASH : 0);
}

/*
 * Connection map
 */

struct util_cmap_handle *ofi_cmap_key2handle(struct util_cmap *cmap, uint64_t key)
{
	struct util_cmap_handle *handle =
		(struct util_cmap_handle *)(uintptr_t)key;

	cmap->acquire(&cmap->lock);
	if (OFI_LIKELY(handle != NULL)) {
#ifdef ENABLE_DEBUG
		if ((handle->key != key)) {
			FI_WARN(cmap->av->prov, FI_LOG_AV,
				"handle->key not matching given key\n");
			handle = NULL;
		}
#endif
	} else {
		FI_WARN(cmap->av->prov, FI_LOG_AV,
			"Invalid key (%"PRIu64")!\n", key);
	}
	cmap->release(&cmap->lock);
	return handle;
}

/* Caller must hold cmap->lock */
static void util_cmap_init_handle(struct util_cmap_handle *handle,
				  struct util_cmap *cmap,
				  enum util_cmap_state state,
				  fi_addr_t fi_addr,
				  struct util_cmap_peer *peer)
{
	handle->cmap = cmap;
	handle->state = state;
	handle->fi_addr = fi_addr;
	handle->peer = peer;
	handle->key = handle;
	if (fi_addr != FI_ADDR_NOTAVAIL)
		cmap->av_handle_table[fi_addr] = handle;
}

static int util_cmap_match_peer(struct dlist_entry *entry, const void *addr)
{
	struct util_cmap_peer *peer =
		container_of(entry, struct util_cmap_peer, entry);
	return !memcmp(peer->addr, addr, peer->handle->cmap->av->addrlen);
}

/* Caller must hold cmap->lock */
static int util_cmap_del_handle(struct util_cmap_handle *handle)
{
	struct util_cmap *cmap = handle->cmap;
	int ret;

	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
	       "Deleting connection handle: %p\n", handle);
	if (handle->peer) {
		dlist_remove(&handle->peer->entry);
		free(handle->peer);
		handle->peer = NULL;
	} else {
		if (handle->fi_addr != FI_ADDR_NOTAVAIL) {
		    cmap->av_handle_table[handle->fi_addr] = NULL;
		}
	}

	handle->state = CMAP_SHUTDOWN;
	/* Signal CM thread to delete the handle. This is required
	 * so that the CM thread handles any pending events for this
	 * ep correctly. Handle would be freed finally after processing the
	 * events */
	ret = cmap->attr.signal(cmap->ep, handle, OFI_CMAP_FREE);
	if (ret) {
		FI_WARN(cmap->av->prov, FI_LOG_FABRIC,
			"Unable to signal CM thread\n");
		return ret;
	}
	return 0;
}

void ofi_cmap_del_handle(struct util_cmap_handle *handle)
{
	struct util_cmap *cmap = handle->cmap;
	cmap->acquire(&cmap->lock);
	util_cmap_del_handle(handle);
	cmap->release(&cmap->lock);
}

/* Caller must hold cmap->lock */
int util_cmap_alloc_handle(struct util_cmap *cmap, fi_addr_t fi_addr,
			   enum util_cmap_state state,
			   struct util_cmap_handle **handle)
{
	*handle = cmap->attr.alloc(cmap);
	if (OFI_UNLIKELY(!*handle))
		return -FI_ENOMEM;
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Allocated handle: %p for "
	       "fi_addr: %" PRIu64 "\n", *handle, fi_addr);
	util_cmap_init_handle(*handle, cmap, state, fi_addr, NULL);
	return 0;
}

/* Caller must hold cmap->lock */
static int util_cmap_alloc_handle_peer(struct util_cmap *cmap, void *addr,
				       enum util_cmap_state state,
				       struct util_cmap_handle **handle)
{
	struct util_cmap_peer *peer;

	peer = calloc(1, sizeof(*peer) + cmap->av->addrlen);
	if (!peer)
		return -FI_ENOMEM;
	*handle = cmap->attr.alloc(cmap);
	if (!*handle) {
		free(peer);
		return -FI_ENOMEM;
	}
	ofi_straddr_dbg(cmap->av->prov, FI_LOG_AV, "Allocated handle for addr",
			addr);
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "handle: %p\n", *handle);
	util_cmap_init_handle(*handle, cmap, state, FI_ADDR_NOTAVAIL, peer);
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Adding handle to peer list\n");
	peer->handle = *handle;
	memcpy(peer->addr, addr, cmap->av->addrlen);
	dlist_insert_tail(&peer->entry, &cmap->peer_list);
	return 0;
}

/* Caller must hold cmap->lock */
static struct util_cmap_handle *
util_cmap_get_handle_peer(struct util_cmap *cmap, const void *addr)
{
	struct util_cmap_peer *peer;
	struct dlist_entry *entry;

	entry = dlist_find_first_match(&cmap->peer_list, util_cmap_match_peer, addr);
	if (!entry)
		return NULL;
	ofi_straddr_dbg(cmap->av->prov, FI_LOG_AV, "handle found in peer list"
			" for addr", addr);
	peer = container_of(entry, struct util_cmap_peer, entry);
	return peer->handle;
}

static int ofi_cmap_move_handle_to_peer_list(struct util_cmap *cmap, fi_addr_t fi_addr)
{
	struct util_cmap_handle *handle = cmap->av_handle_table[fi_addr];
	struct util_av_entry *av_entry =
		util_buf_get_by_index(cmap->av->av_entry_pool, fi_addr);
	int ret = 0;

	cmap->acquire(&cmap->lock);
	if (!handle)
		goto unlock;

	handle->peer = calloc(1, sizeof(*handle->peer) + cmap->av->addrlen);
	if (!handle->peer) {
		ret = -FI_ENOMEM;
		goto unlock;
	}
	handle->peer->handle = handle;
	memcpy(handle->peer->addr, av_entry->addr, cmap->av->addrlen);
	dlist_insert_tail(&handle->peer->entry, &cmap->peer_list);
unlock:
	cmap->release(&cmap->lock);
	return ret;
}

/* Caller must hold cmap->lock */
static void util_cmap_move_handle(struct util_cmap_handle *handle,
				  fi_addr_t fi_addr)
{
	dlist_remove(&handle->peer->entry);
	free(handle->peer);
	handle->peer = NULL;
	handle->fi_addr = fi_addr;
	handle->cmap->av_handle_table[fi_addr] = handle;
}

int ofi_cmap_update(struct util_cmap *cmap, const void *addr, fi_addr_t fi_addr)
{
	struct util_cmap_handle *handle;
	int ret = 0;

	cmap->acquire(&cmap->lock);
	handle = util_cmap_get_handle_peer(cmap, addr);
	if (!handle) {
		ret = util_cmap_alloc_handle(cmap, fi_addr, CMAP_IDLE, &handle);
		cmap->release(&cmap->lock);
		return ret;
	}
	util_cmap_move_handle(handle, fi_addr);
	cmap->release(&cmap->lock);

	if (cmap->attr.av_updated_handler)
		cmap->attr.av_updated_handler(handle);
	return 0;
}

/* Caller must hold cmap->lock */

void ofi_cmap_process_shutdown(struct util_cmap *cmap,
			       struct util_cmap_handle *handle)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
		"Processing shutdown for handle: %p\n", handle);
	cmap->acquire(&cmap->lock);
	if (handle->state > CMAP_SHUTDOWN) {
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL,
			"Invalid handle on shutdown event\n");
	} else if (handle->state != CMAP_SHUTDOWN) {
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Got remote shutdown\n");
		util_cmap_del_handle(handle);
	} else {
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Got local shutdown\n");
	}
	cmap->release(&cmap->lock);
}

/* Caller must hold cmap->lock */
void ofi_cmap_process_conn_notify(struct util_cmap *cmap,
				  struct util_cmap_handle *handle)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
	       "Processing connection notification for handle: %p.\n", handle);
	handle->state = CMAP_CONNECTED;
	cmap->attr.connected_handler(handle);
}

/* Caller must hold cmap->lock */
void ofi_cmap_process_connect(struct util_cmap *cmap,
			      struct util_cmap_handle *handle,
			      uint64_t *remote_key)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
	       "Processing connect for handle: %p\n", handle);
	handle->state = CMAP_CONNECTED_NOTIFY;
	if (remote_key)
		handle->remote_key = *remote_key;
}

void ofi_cmap_process_reject(struct util_cmap *cmap,
			     struct util_cmap_handle *handle,
			     enum util_cmap_reject_flag cm_reject_flag)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
		"Processing reject for handle: %p\n", handle);
	cmap->acquire(&cmap->lock);
	switch (handle->state) {
	case CMAP_CONNREQ_RECV:
	case CMAP_CONNECTED:
	case CMAP_CONNECTED_NOTIFY:
		/* Handle is being re-used for incoming connection request */
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			"Connection handle is being re-used. Close saved connection\n");
		handle->cmap->attr.close_saved_conn(handle);
		break;
	case CMAP_CONNREQ_SENT:
		if (cm_reject_flag == CMAP_REJECT_GENUINE) {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			       "Deleting connection handle\n");
			util_cmap_del_handle(handle);
		} else {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			       "Connection handle is being re-used. Close the connection\n");
			handle->cmap->attr.close(handle);
		}
		break;
	case CMAP_SHUTDOWN:
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			"Connection handle already being deleted\n");
		break;
	default:
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL, "Invalid cmap state: "
			"%d when receiving connection reject\n", handle->state);
		assert(0);
	}
	cmap->release(&cmap->lock);
}

int ofi_cmap_process_connreq(struct util_cmap *cmap, void *addr,
			     struct util_cmap_handle **handle_ret,
			     enum util_cmap_reject_flag *cm_reject_flag)
{
	struct util_cmap_handle *handle;
	int ret = 0, cmp;
	fi_addr_t fi_addr;

	/* Reset flag to initial state */
	*cm_reject_flag = CMAP_REJECT_GENUINE;

	ofi_straddr_dbg(cmap->av->prov, FI_LOG_EP_CTRL,
			"Processing connreq for addr", addr);

	fi_addr = ip_av_get_fi_addr(cmap->av, addr);

	cmap->acquire(&cmap->lock);
	if (fi_addr == FI_ADDR_NOTAVAIL)
		handle = util_cmap_get_handle_peer(cmap, addr);
	else {
		handle = ofi_cmap_acquire_handle(cmap, fi_addr);
	}

	if (!handle) {
		if (fi_addr == FI_ADDR_NOTAVAIL)
			ret = util_cmap_alloc_handle_peer(cmap, addr,
							  CMAP_CONNREQ_RECV,
							  &handle);
		else
			ret = util_cmap_alloc_handle(cmap, fi_addr,
						     CMAP_CONNREQ_RECV,
						     &handle);
		if (ret)
			goto unlock;
	}

	switch (handle->state) {
	case CMAP_CONNECTED_NOTIFY:
	case CMAP_CONNECTED:
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			"Connection already present.\n");
		ret = -FI_EALREADY;
		break;
	case CMAP_CONNREQ_SENT:
		ofi_straddr_dbg(cmap->av->prov, FI_LOG_EP_CTRL, "local_name",
				cmap->attr.name);
		ofi_straddr_dbg(cmap->av->prov, FI_LOG_EP_CTRL, "remote_name",
				addr);

		cmp = ofi_addr_cmp(cmap->av->prov, addr, cmap->attr.name);

		if (cmp < 0) {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
				"Remote name lower than local name.\n");
			*cm_reject_flag = CMAP_REJECT_SIMULT_CONN;
			ret = -FI_EALREADY;
			break;
		} else if (cmp > 0) {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
				"Re-using handle: %p to accept remote "
				"connection\n", handle);
			/* Re-use handle. If it receives FI_REJECT the handle
			 * would not be deleted in this state */
			//handle->cmap->attr.close(handle);
			handle->cmap->attr.save_conn(handle);
		} else {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
				"Endpoint connects to itself\n");
			ret = util_cmap_alloc_handle_peer(cmap, addr,
							  CMAP_CONNREQ_RECV,
							  &handle);
			if (ret)
				goto unlock;
			assert(fi_addr != FI_ADDR_NOTAVAIL);
			handle->fi_addr = fi_addr;
		}
		/* Fall through */
	case CMAP_IDLE:
		handle->state = CMAP_CONNREQ_RECV;
		/* Fall through */
	case CMAP_CONNREQ_RECV:
		*handle_ret = handle;
		break;
	default:
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL,
		       "Invalid cmap state\n");
		assert(0);
		ret = -FI_EOPBADSTATE;
	}
unlock:
	cmap->release(&cmap->lock);
	return ret;
}

/* Caller must hold `cmap::lock` */
int ofi_cmap_handle_connect(struct util_cmap *cmap, fi_addr_t fi_addr,
			    struct util_cmap_handle *handle)
{
	int ret;
	struct util_av_entry *av_entry;

	if (handle->state == CMAP_CONNECTED_NOTIFY ||
	    handle->state == CMAP_CONNECTED)
		return FI_SUCCESS;

	switch (handle->state) {
	case CMAP_IDLE:
		av_entry = util_buf_get_by_index(cmap->av->av_entry_pool, fi_addr);
		assert(av_entry);
		ret = cmap->attr.connect(cmap->ep, handle, av_entry->addr,
					 cmap->av->addrlen);
		if (ret) {
			util_cmap_del_handle(handle);
			return ret;
		}
		handle->state = CMAP_CONNREQ_SENT;
		ret = -FI_EAGAIN;
		// TODO sleep on event fd instead of busy polling
		break;
	case CMAP_CONNREQ_SENT:
	case CMAP_CONNREQ_RECV:
	case CMAP_ACCEPT:
	case CMAP_SHUTDOWN:
		ret = -FI_EAGAIN;
		break;
	default:
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL,
			"Invalid cmap handle state\n");
		assert(0);
		ret = -FI_EOPBADSTATE;
	}
	return ret;
}

int ofi_cmap_get_handle(struct util_cmap *cmap, fi_addr_t fi_addr,
			struct util_cmap_handle **handle_ret)
{
	int ret;

	cmap->acquire(&cmap->lock);
	*handle_ret = ofi_cmap_acquire_handle(cmap, fi_addr);
	if (OFI_UNLIKELY(!*handle_ret)) {
		ret = -FI_EAGAIN;
		goto unlock;
	}
	
	ret = ofi_cmap_handle_connect(cmap, fi_addr, *handle_ret);
unlock:
	cmap->release(&cmap->lock);
	return ret;
}

static int util_cmap_cm_thread_close(struct util_cmap *cmap)
{
	int ret;

	ret = cmap->attr.signal(cmap->ep, NULL, OFI_CMAP_EXIT);
	if (ret) {
		FI_WARN(cmap->av->prov, FI_LOG_FABRIC,
			"Unable to signal CM thread\n");
		return ret;
	}
	/* Release lock so that CM thread could process shutdown events */
	cmap->release(&cmap->lock);
	ret = pthread_join(cmap->cm_thread, NULL);
	cmap->acquire(&cmap->lock);
	if (ret) {
		FI_WARN(cmap->av->prov, FI_LOG_FABRIC,
			"Unable to join CM thread\n");
		return ret;
	}
	return 0;
}

void ofi_cmap_free(struct util_cmap *cmap)
{
	struct util_cmap_peer *peer;
	struct dlist_entry *entry;
	size_t i;

	cmap->acquire(&cmap->lock);
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Closing cmap, size - %d\n",
	       cmap->av->count);
	for (i = 0; i < cmap->av->count; i++) {
		if (cmap->av_handle_table[i])
			util_cmap_del_handle(cmap->av_handle_table[i]);
	}
	while (!dlist_empty(&cmap->peer_list)) {
		entry = cmap->peer_list.next;
		peer = container_of(entry, struct util_cmap_peer, entry);
		util_cmap_del_handle(peer->handle);
	}
	util_cmap_cm_thread_close(cmap);
	cmap->release(&cmap->lock);

	/* cleanup function would be used in manual progress mode */
	if (cmap->attr.cleanup) {
		cmap->attr.cleanup(cmap->ep);
	}
	free(cmap->av_handle_table);
	free(cmap->attr.name);
	if (!cmap->attr.serial_access)
		fastlock_destroy(&cmap->lock);
	free(cmap);
}

struct util_cmap *ofi_cmap_alloc(struct util_ep *ep,
				 struct util_cmap_attr *attr)
{
	struct util_cmap *cmap;

	cmap = calloc(1, sizeof *cmap);
	if (!cmap)
		return NULL;

	cmap->ep = ep;
	cmap->av = ep->av;

	cmap->av_handle_table = calloc(cmap->av->count,
				       sizeof(**cmap->av_handle_table));

	cmap->attr = *attr;
	cmap->attr.name = mem_dup(attr->name, ep->av->addrlen);
	if (!cmap->attr.name)
		goto err1;

	dlist_init(&cmap->peer_list);

	if (pthread_create(&cmap->cm_thread, 0,
			   cmap->attr.cm_thread_func, ep)) {
		FI_WARN(ep->av->prov, FI_LOG_FABRIC,
			"Unable to create cmap thread\n");
		goto err2;
	}

	if (cmap->attr.serial_access) {
		cmap->acquire = ofi_fastlock_acquire_noop;
		cmap->release = ofi_fastlock_release_noop;
	} else {
		fastlock_init(&cmap->lock);
		cmap->acquire = ofi_fastlock_acquire;
		cmap->release = ofi_fastlock_release;
	}
	return cmap;
err2:
	free(cmap->attr.name);
err1:
	free(cmap);
	return NULL;
}
