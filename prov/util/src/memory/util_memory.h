#include <fi_util.h>
#include <sys/mman.h>

void *ofi_util_mem_override_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int ofi_util_mem_override_munmap(void *addr, size_t length);
void *ofi_util_mem_override_mremap(void *old_address, size_t old_size, size_t new_size, int flags);
void *ofi_util_mem_override_shmat(int shmid, const void *shmaddr, int shmflg);
int ofi_util_mem_override_shmdt(const void *shmaddr);
void *ofi_util_mem_override_sbrk(intptr_t increment);

#define OFI_UTIL_MEM_OVEREIDE_SYM(sym, event)					\
	{									\
		{							\
			#sym,					\
			ofi_util_mem_override_ ## sym,	\
			NULL,				\
			{ 0, 0 }					\
		},								\
		event						\
	}

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
