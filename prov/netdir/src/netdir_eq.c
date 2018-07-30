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

#include "netdir.h"
#include "netdir_log.h"
#include "netdir_misc.h"

#include "ofi_util.h"

int ofi_nd_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		   struct fid_eq **peq, void *context);
static int ofi_nd_eq_close(struct fid *fid);
static ssize_t ofi_nd_eq_read(struct fid_eq *peq, uint32_t *pev,
			      void *buf, size_t len, uint64_t flags);
static ssize_t ofi_nd_eq_readerr(struct fid_eq *peq,
				 struct fi_eq_err_entry *buf, uint64_t flags);
static ssize_t ofi_nd_eq_sread(struct fid_eq *peq, uint32_t *pev,
			       void *buf, size_t len, int timeout,
			       uint64_t flags);
static const char *ofi_nd_eq_strerror(struct fid_eq *eq, int prov_errno,
				      const void *err_data, char *buf, size_t len);
static ssize_t ofi_nd_eq_write(struct fid_eq *peq, uint32_t ev,
			       const void *buf, size_t len, uint64_t flags);

static struct fi_ops ofi_nd_fi_ops = {
	.size = sizeof(ofi_nd_fi_ops),
	.close = ofi_nd_eq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_eq ofi_nd_eq_ops = {
	.size = sizeof(ofi_nd_eq_ops),
	.read = ofi_nd_eq_read,
	.readerr = ofi_nd_eq_readerr,
	.write = ofi_nd_eq_write,
	.sread = ofi_nd_eq_sread,
	.strerror = ofi_nd_eq_strerror
};

int ofi_nd_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		   struct fid_eq **peq, void *context)
{
	if (!peq || !fabric || fabric->fid.fclass != FI_CLASS_FABRIC)
		return -FI_EINVAL;

	if (attr)
	{
		if (attr->wait_obj != FI_WAIT_NONE && attr->wait_obj != FI_WAIT_UNSPEC)
			return -FI_EBADFLAGS;
	}

	nd_eq_t *nd_eq_ptr = (nd_eq_t*)calloc(1, sizeof(*nd_eq_ptr));
	if (!nd_eq_ptr)
		return -FI_ENOMEM;

	nd_eq_ptr->fid.fid.fclass = FI_CLASS_EQ;
	nd_eq_ptr->fid.fid.context = context;
	nd_eq_ptr->fid.fid.ops = &ofi_nd_fi_ops;
	nd_eq_ptr->fid.ops = &ofi_nd_eq_ops;
	nd_eq_ptr->count = 0;

	*peq = &nd_eq_ptr->fid;

	return FI_SUCCESS;
}

static int ofi_nd_eq_close(struct fid *fid)
{
	return FI_SUCCESS;
}

static ssize_t ofi_nd_eq_read(struct fid_eq *peq, uint32_t *pev,
			      void *buf, size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_eq_readerr(struct fid_eq *peq,
				 struct fi_eq_err_entry *buf, uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t ofi_nd_eq_sread(struct fid_eq *peq, uint32_t *pev,
			       void *buf, size_t len, int timeout,
			       uint64_t flags)
{
	nd_eq_t *nd_eq_ptr = container_of(peq, struct nd_eq, fid);
	nd_eq_ptr->count = 0;
	while (!nd_eq_ptr->count) {
		LONG zero = 0;
		if (!WaitOnAddress(
			&nd_eq_ptr->count, &zero, sizeof(nd_eq_ptr->count),
			(DWORD)timeout) && timeout >= 0)
			return -FI_EAGAIN;
	}
	int server_finally_read_something = 0;
	assert(server_finally_read_something);
	return FI_SUCCESS;
}

static const char *ofi_nd_eq_strerror(struct fid_eq *eq, int prov_errno,
				      const void *err_data, char *buf, size_t len)
{
	return NULL;
}

static ssize_t ofi_nd_eq_write(struct fid_eq *peq, uint32_t ev,
			       const void *buf, size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

#endif /* _WIN32 */
