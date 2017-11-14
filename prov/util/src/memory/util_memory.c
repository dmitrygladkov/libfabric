#include "util_memory.h"

static pthread_mutex_t mem_override_install_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ofi_util_mem_override_sym mem_override_sym[6];

static void *(*prev_dlopen_func)(const char *, int) = NULL;
DEFINE_LIST(overrided_sym_list);
static pthread_mutex_t overrided_sym_list_lock = PTHREAD_MUTEX_INITIALIZER;

static void *util_mem_dlopen(const char *filename, int flag)
{
	void *dlopen_ret;

	if (!prev_dlopen_func)
		return NULL;

	dlopen_ret = prev_dlopen_func(filename, flags);
	if (dlopen_ret) {
		pthread_mutex_lock(&overrided_sym_list_lock);
		pthread_mutex_unlock(&overrided_sym_list_lock);
	}
	return dlopen_ret;
}

static int util_mem_override_sym(struct ofi_util_mem_override_sym *sym)
{
}

static int util_mem_override_install(uint64_t events)
{
	size_t i = 0;
	int ret;

	pthread_mutex_lock(&mem_override_install_lock);

	for (i = 0; i < 6; i++) {
		if (mem_override_sym[i]->event & events)
			continue;
		ret = ;
		if (ret)
			return ret;
	}

	pthread_mutex_unlock(&mem_override_install_lock);
	return FI_SUCCESS;
}

