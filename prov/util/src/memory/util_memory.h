#include <fi_util.h>
#include <sys/mman.h>

static inline void *ofi_util_mem_override_mmap(void *addr, size_t length, int prot,
					       int flags, int fd, off_t offset)
{
	return NULL;
}
static inline int ofi_util_mem_override_munmap(void *addr, size_t length)
{
	return 0;
}
static inline void *ofi_util_mem_override_mremap(void *old_address, size_t old_size,
						 size_t new_size, int flags)
{
	return NULL;
}
static inline void *ofi_util_mem_override_shmat(int shmid, const void *shmaddr,
						int shmflg)
{
	return NULL;
}
static inline int ofi_util_mem_override_shmdt(const void *shmaddr)
{
	return 0;
}
static inline void *ofi_util_mem_override_sbrk(intptr_t increment)
{
	return NULL;
}

static inline void ofi_util_mem_free(void *ptr, const void *caller)
{
	return;
}

static inline void *ofi_util_mem_malloc(size_t size, const void *caller)
{
	return NULL;
}

static inline void *ofi_util_mem_realloc(void *oldptr, size_t size,
					 const void *caller)
{
	return NULL;
}

static inline void *ofi_util_mem_memalign(size_t alignment, size_t size,
					  const void *caller)
{
	return NULL;
}

static inline void *ofi_util_mem_calloc(size_t nmemb, size_t size)
{
	return NULL;
}

static inline void *ofi_util_mem_valloc(size_t size)
{
	return NULL;
}

static inline int ofi_util_mem_posix_memalign(void **memptr, size_t alignment,
					      size_t size)
{
	return 0;
}

static inline int ofi_util_mem_setenv(const char *name, const char *value,
				      int overwrite)
{
	return -1;
}

static inline void *ofi_util_mem_cpp_scalar_new(size_t size)
{
	return NULL;
}

static inline void ofi_util_mem_cpp_scalar_delete(void* ptr)
{
	return;
}

static inline void *ofi_util_mem_cpp_vector_new(size_t size)
{
	return NULL;
}

static inline void ofi_util_mem_cpp_vector_delete(void* ptr)
{
	return;
}

#define OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(sym)			\
	{							\
		#sym,						\
		ofi_util_mem_ ## sym,				\
	}

#define OFI_UTIL_MEM_DEFINE_OVERRIDE_CPP_SYM(sym)		\
	{							\
		ofi_util_mem_cpp_ ## sym ## _sym,		\
		ofi_util_mem_cpp_ ## sym,			\
	}

#define OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM_EX(sym, event)		\
	{							\
		{						\
			#sym,					\
			ofi_util_mem_override_ ## sym,		\
		},						\
		event,						\
	}

/*#if HAVE_GLIBC_MALLOC_HOOK*/
#define OFI_UTIL_MEM_GLIBC_HOOK(hook)		\
	__ ## hook ## _hook
#define OFI_UTIL_MEM_RET_GLIBC_NULL_HOOK				\
	({								\
		assert(0 && "Unable to find an appropriate "		\
		       "Glibc memory hook. Something is going wrong");	\
		NULL;							\
	})
#define OFI_UTIL_MEM_GET_GLIBC_HOOK_PTR(sym_name)					\
	(!strcmp(sym_name, "free")	  ? &OFI_UTIL_MEM_GLIBC_HOOK(free)	:	\
	 (!strcmp(sym_name, "realloc")	  ? &OFI_UTIL_MEM_GLIBC_HOOK(realloc)	:	\
	  (!strcmp(sym_name, "malloc")	  ? &OFI_UTIL_MEM_GLIBC_HOOK(malloc)	:	\
	   (!strcmp(sym_name, "memalign") ? &OFI_UTIL_MEM_GLIBC_HOOK(memalign)	:	\
					    OFI_UTIL_MEM_RET_GLIBC_NULL_HOOK))))
		
#define OFI_UTIL_MEM_INSTALL_HOOK(hook, over_sym)			\
	({								\
		(hook) = (over_sym)->func;				\
		FI_SUCCESS;						\
	})
/*#else /* !HAVE_GLIBC_MALLOC_HOOK */
/*#define OFI_UTIL_MEM_GET_GLIBC_HOOK_PTR(sym_name) NULL /* Returns NULL aleways */
/*#define OFI_UTIL_MEM_INSTALL_HOOK(hook, over_sym)*/
/*({ /* Do nothing if Glibc hooks aren't defined*/
/* OFI_UNUSED(hook);*/
/* OFI_UNUSED(over_sym);*/
/* })*/
/*#endif /* HAVE_GLIBC_MALLOC_HOOK */

#define OFI_UTIL_MEM_INSTALL_MALLOC_SYM(over_sym, over_sym_list)		\
	({									\
		int ret = util_mem_override_sym(over_sym);			\
		if (!ret)							\
			dlist_insert_tail(&(over_sym)->list_entry,		\
					  over_sym_list);			\
		ret;								\
	})

struct ofi_util_mem_override_sym {
	const char		*func_symbol;
	void			*func;
	void			*prev_func;
	struct dlist_entry	list_entry;
};

enum ofi_util_mem_event_type {
	OFI_MEM_MMAP_EVENT	= 1 << 1,
	OFI_MEM_MUNMAP_EVENT	= 1 << 2,
	OFI_MEM_MREMAP_EVENT	= 1 << 3,
	OFI_MEM_SHMAT_EVENT	= 1 << 4,
	OFI_MEM_SHMDT_EVENT	= 1 << 5,
	OFI_MEM_SBRK_EVENT	= 1 << 6,
};

struct ofi_util_mem_override {
	struct ofi_util_mem_override_sym	ov_sym;
	enum ofi_util_mem_event_type		event;
};
