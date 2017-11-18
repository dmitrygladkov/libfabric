#include "util_memory.h"
#include <sys/auxv.h>
#include <dlfcn.h>
#include <link.h>

#define ofi_util_mem_cpp_scalar_new_sym		"_Znwm"
#define ofi_util_mem_cpp_scalar_delete_sym	"_ZdlPv"
#define ofi_util_mem_cpp_vector_new_sym		"_Znam"
#define ofi_util_mem_cpp_vector_delete_sym	"_ZdaPv"

#ifdef __x86_64__
#define ELFW(x) ELF64_ ## x
#elif defined(__i386__)
#define ELFW(x) ELF32_ ## x
#endif

struct util_mem_override_sym_dl {
	struct ofi_util_mem_override_sym *sym;
	int ret;
};

static pthread_mutex_t mem_override_install_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ofi_util_mem_override mem_override_sym[] = {
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM_EX(mmap, OFI_MEM_MMAP_EVENT),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM_EX(munmap, OFI_MEM_MUNMAP_EVENT),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM_EX(mremap, OFI_MEM_MREMAP_EVENT),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM_EX(shmat, OFI_MEM_SHMAT_EVENT),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM_EX(shmdt, OFI_MEM_SHMDT_EVENT),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM_EX(sbrk, OFI_MEM_SBRK_EVENT),
};
static struct ofi_util_mem_override_sym mem_override_malloc_sym[] = {
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(free),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(realloc),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(malloc),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(memalign),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(calloc),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(valloc),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(posix_memalign),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_SYM(setenv),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_CPP_SYM(scalar_new),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_CPP_SYM(scalar_delete),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_CPP_SYM(vector_new),
	OFI_UTIL_MEM_DEFINE_OVERRIDE_CPP_SYM(vector_delete),
};

static void *(*prev_dlopen_func)(const char *, int) = NULL;
DEFINE_LIST(overrided_sym_list);
static pthread_mutex_t overrided_sym_list_lock = PTHREAD_MUTEX_INITIALIZER;

static uintptr_t util_mem_get_elf_table_ptr(ElfW(Addr) dlpi_addr,
					    const ElfW(Phdr) *dlpi_phdr,
					    ElfW(Sword) d_tag)
{
	ElfW(Dyn) *dyn_section_array = (ElfW(Dyn) *)(dlpi_phdr->p_vaddr + dlpi_addr);
	for (; dyn_section_array->d_tag != DT_NULL; ++dyn_section_array)
		if (dyn_section_array->d_tag == d_tag)
			/* There are no any differencies whatever this func returns
			 * (`d_ptr` or `d_val`), because `d_un` is an union.
			 * Just it's necessary to cast to whatever type base on
			 * caller's needs */
			return dyn_section_array->d_un.d_ptr;
	return 0;
}

static inline ElfW(Sym)* util_mem_get_sym(ElfW(Sym)* symtab, size_t idx)
{
	if ((ELFW(ST_BIND)(symtab[idx].st_info) == STB_WEAK) &&
	     !symtab[idx].st_value)
		return NULL;
	return &symtab[idx];
}

static int util_mem_replace_sym(ElfW(Addr) dlpi_addr, unsigned long page_size,
				void *dt_jmprel, size_t dt_pltrelsz,
				void *dt_strtab, ElfW(Sym) *dt_symtab,
				struct ofi_util_mem_override_sym *sym)
{
	ElfW(Rela) *rela = dt_jmprel;
	void *plt_rel_end = (char *)dt_jmprel + dt_pltrelsz;
	char *symbol_name;
	ElfW(Sym) *sym_table;

	for (; (void *)rela < plt_rel_end; ++rela) {
		sym_table = util_mem_get_sym(dt_symtab,
					     ELFW(R_SYM)(rela->r_info));
		if (!sym_table)
			continue;
		symbol_name = (char *)dt_strtab + sym_table->st_name;
		if (!strcmp(sym->func_symbol, symbol_name)) {
			void **replaced = (void **)(dlpi_addr + rela->r_offset);
			if (mprotect((void *)((intptr_t)replaced & ~(page_size - 1)),
					   page_size, PROT_READ | PROT_WRITE) < 0) {
				assert(0);
				return -ofi_syserr();
			}
			sym->prev_func = *replaced;
			*replaced = sym->func;
			break;
		}
	}

	return FI_SUCCESS;
}

static int util_mem_modify_got_page(struct dl_phdr_info *info,
				    unsigned long ph_size,
				    unsigned long page_size,
				    struct ofi_util_mem_override_sym *sym)
{
	int i;
	void *dt_jmprel; /* addr of PLT relocs */
	size_t dt_pltrelsz; /* size in bytes of PLT relocs */
	void *dt_strtab; /* addr of string table */
	ElfW(Sym) *dt_symtab; /* addr of symbol tabel */

	/* Since the ELF spec says that:
	 * "An object file may have obly onde dynamic section",
	 * Let's assume that that a shared object has only one `PT_DYNAMIC`
	 */
	for (i = 0; ((i < info->dlpi_phnum) &&
		     (info->dlpi_phdr[i].p_type != PT_DYNAMIC)); i++) ;
	if (i == info->dlpi_phnum) {
		assert(0);
		return -FI_ENODATA;
	}

	dt_pltrelsz = (size_t)util_mem_get_elf_table_ptr(info->dlpi_addr,
							 &info->dlpi_phdr[i],
							 DT_PLTRELSZ);
	dt_jmprel = (void *)util_mem_get_elf_table_ptr(info->dlpi_addr,
						       &info->dlpi_phdr[i],
						       DT_JMPREL);
	dt_strtab = (void *)util_mem_get_elf_table_ptr(info->dlpi_addr,
						       &info->dlpi_phdr[i],
						       DT_STRTAB);
	dt_symtab = (ElfW(Sym) *)util_mem_get_elf_table_ptr(info->dlpi_addr,
							    &info->dlpi_phdr[i],
							    DT_SYMTAB);
	return util_mem_replace_sym(info->dlpi_addr, page_size,
				    dt_jmprel, dt_pltrelsz,
				    dt_strtab, dt_symtab, sym);
}

static int util_mem_override_dl_phdr_iterator(struct dl_phdr_info *info,
					      size_t size, void *data)
{
	struct util_mem_override_sym_dl *sym_dl = data;
	unsigned long ph_size;
	unsigned long page_size;

	/* Retrieves the size of the program header entry */
	ph_size = getauxval(AT_PHENT);
	if (!ph_size) {
		assert(0);
		return -FI_ENOENT;
	}

	/* Retrieves the page size */
	page_size = getauxval(AT_PAGESZ);
	if (!page_size) {
		assert(0);
		return -FI_ENOENT;
	}

	sym_dl->ret = util_mem_modify_got_page(info, ph_size, page_size,
					       sym_dl->sym);
	return sym_dl->ret;
}

/* Must be called with lock held */
static int util_mem_override_sym(struct ofi_util_mem_override_sym *sym)
{
	struct util_mem_override_sym_dl override_sym_dl = {
		.sym = sym,
		.ret = FI_SUCCESS,
	};
	int ret;

	/* `dl_iterate_phdr` returns the last return value of the
	 * `util_mem_override_dl_phdr_iterator` callback.
	 *
	 * This part of code assumes that this value is `FI_SUCCESS`
	 * in case of walking through list of shared objects were succesfull
	 * and we can go ahead. */
	ret = dl_iterate_phdr(util_mem_override_dl_phdr_iterator, &override_sym_dl);
	if (ret)
		assert(0);

	return ret;
}

static void *util_mem_dlopen(const char *filename, int flags)
{
	void *dlopen_ret;
	struct ofi_util_mem_override_sym *sym_entry;

	if (!prev_dlopen_func) {
		assert(0);
		return NULL;
	}

	dlopen_ret = prev_dlopen_func(filename, flags);
	if (dlopen_ret) {
		pthread_mutex_lock(&overrided_sym_list_lock);
		dlist_foreach_container(&overrided_sym_list,
					struct ofi_util_mem_override_sym,
					sym_entry, list_entry) {
			util_mem_override_sym(sym_entry);
		}
		pthread_mutex_unlock(&overrided_sym_list_lock);
	}
	return dlopen_ret;
}

/* Must be called with lock held */
static int util_mem_override_install_dlopen(void)
{
	static int is_already_installed = 0;
	int ret;
	void *func;
	struct ofi_util_mem_override_sym dlopen_sym = {
		.func_symbol = "dlopen",
		.func = util_mem_dlopen,
	};

	if (is_already_installed)
		return FI_SUCCESS;

	func = dlsym(RTLD_NEXT, dlopen_sym.func_symbol);
	if (!func) {
		func = dlsym(RTLD_DEFAULT, dlopen_sym.func_symbol);
		if (func == dlopen_sym.func)
			assert(0);
	}
	prev_dlopen_func = func;

	ret = util_mem_override_sym(&dlopen_sym);
	if (ret)
		return ret;
	is_already_installed = 1;
	return FI_SUCCESS;
}

static int util_mem_override_install(uint64_t events)
{
	static int installed_events = 0;
	size_t i = 0;
	int ret = FI_SUCCESS;

	pthread_mutex_lock(&mem_override_install_lock);

	ret = util_mem_override_install_dlopen();
	if (ret)
		goto fn;

	for (i = 0; i < 6; i++) {
		if ((mem_override_sym[i].event & events) ||
		    (mem_override_sym[i].event & installed_events))
			continue;
		ret = util_mem_override_sym(&mem_override_sym[i].ov_sym);
		if (ret)
			goto fn;

		dlist_insert_tail(&mem_override_sym[i].ov_sym.list_entry,
				  &overrided_sym_list);
		installed_events |= mem_override_sym[i].event;
	}
fn:
	pthread_mutex_unlock(&mem_override_install_lock);
	return ret;
}

