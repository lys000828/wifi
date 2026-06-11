/**
 * Minimal PLT/GOT hook implementation for Android.
 * Scans /proc/self/maps to find loaded ELF libraries,
 * then patches their GOT entries for target symbols.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <android/log.h>
#include <link.h>

#include <inttypes.h>

#include "plt_hook.h"

#define LOG_TAG "NativeHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifdef __LP64__
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym  Elf_Sym;
typedef Elf64_Rel  Elf_Rel;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Dyn  Elf_Dyn;
typedef Elf64_Word Elf_Word;
#define ELF_R_SYM(x) ELF64_R_SYM(x)
#define ELF_R_TYPE(x) ELF64_R_TYPE(x)
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym  Elf_Sym;
typedef Elf32_Rel  Elf_Rel;
typedef Elf32_Rela Elf_Rela;
typedef Elf32_Dyn  Elf_Dyn;
typedef Elf32_Word Elf_Word;
#define ELF_R_SYM(x) ELF32_R_SYM(x)
#define ELF_R_TYPE(x) ELF32_R_TYPE(x)
#endif

#define MAX_HOOKS 32

typedef struct {
    const char *symbol;
    void *new_func;
    void **old_func;
} hook_entry_t;

static hook_entry_t g_hooks[MAX_HOOKS];
static int g_hook_count = 0;

int plt_hook_register(const char *symbol, void *new_func, void **old_func) {
    if (g_hook_count >= MAX_HOOKS) return -1;
    g_hooks[g_hook_count].symbol = symbol;
    g_hooks[g_hook_count].new_func = new_func;
    g_hooks[g_hook_count].old_func = old_func;
    g_hook_count++;
    return 0;
}

static int patch_got_entry(uintptr_t got_addr, void *new_val, void **old_val) {
    // Make the GOT entry writable
    uintptr_t page_start = got_addr & ~(uintptr_t)(getpagesize() - 1);
    size_t page_size = getpagesize();

    if (mprotect((void *)page_start, page_size, PROT_READ | PROT_WRITE) != 0) {
        // Try with exec permission
        if (mprotect((void *)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            return -1;
        }
    }

    // Save old value and write new
    if (old_val) {
        *old_val = *(void **)got_addr;
    }
    *(void **)got_addr = new_val;

    // Restore protection
    mprotect((void *)page_start, page_size, PROT_READ);

    return 0;
}

static void hook_single_lib(uintptr_t base_addr, const char *lib_name) {
    if (base_addr == 0) return;

    Elf_Ehdr *ehdr = (Elf_Ehdr *)base_addr;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return;

    Elf_Phdr *phdr = (Elf_Phdr *)(base_addr + ehdr->e_phoff);
    Elf_Dyn *dynamic = NULL;
    uintptr_t load_bias = base_addr;

    // Find PT_DYNAMIC
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (Elf_Dyn *)(load_bias + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynamic) return;

    // Parse dynamic section
    Elf_Sym *symtab = NULL;
    const char *strtab = NULL;
    Elf_Rel *rel_plt = NULL;
    Elf_Rela *rela_plt = NULL;
    size_t rel_plt_size = 0;
    size_t rela_plt_size = 0;
    int is_rela = 0;

    for (Elf_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:
                symtab = (Elf_Sym *)(load_bias + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (const char *)(load_bias + dyn->d_un.d_ptr);
                break;
            case DT_JMPREL:
                rel_plt = (Elf_Rel *)(load_bias + dyn->d_un.d_ptr);
                rela_plt = (Elf_Rela *)(load_bias + dyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                rel_plt_size = dyn->d_un.d_val;
                rela_plt_size = dyn->d_un.d_val;
                break;
            case DT_PLTREL:
                is_rela = (dyn->d_un.d_val == DT_RELA);
                break;
        }
    }

    if (!symtab || !strtab || (!rel_plt && !rela_plt)) return;

    // Iterate relocations and patch
    if (is_rela && rela_plt) {
        size_t count = rela_plt_size / sizeof(Elf_Rela);
        for (size_t i = 0; i < count; i++) {
            unsigned int sym_idx = ELF_R_SYM(rela_plt[i].r_info);
            const char *sym_name = strtab + symtab[sym_idx].st_name;

            for (int h = 0; h < g_hook_count; h++) {
                if (strcmp(sym_name, g_hooks[h].symbol) == 0) {
                    uintptr_t got_addr = load_bias + rela_plt[i].r_offset;
                    void *current = *(void **)got_addr;
                    if (current != g_hooks[h].new_func) {
                        patch_got_entry(got_addr, g_hooks[h].new_func, g_hooks[h].old_func);
                    }
                    break;
                }
            }
        }
    } else if (rel_plt) {
        size_t count = rel_plt_size / sizeof(Elf_Rel);
        for (size_t i = 0; i < count; i++) {
            unsigned int sym_idx = ELF_R_SYM(rel_plt[i].r_info);
            const char *sym_name = strtab + symtab[sym_idx].st_name;

            for (int h = 0; h < g_hook_count; h++) {
                if (strcmp(sym_name, g_hooks[h].symbol) == 0) {
                    uintptr_t got_addr = load_bias + rel_plt[i].r_offset;
                    void *current = *(void **)got_addr;
                    if (current != g_hooks[h].new_func) {
                        patch_got_entry(got_addr, g_hooks[h].new_func, g_hooks[h].old_func);
                    }
                    break;
                }
            }
        }
    }
}

int plt_hook_commit() {
    if (g_hook_count == 0) return 0;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // Parse: start-end perms offset dev inode pathname
        if (strstr(line, " r-xp ") == NULL && strstr(line, " r--p ") == NULL) continue;

        unsigned long start_addr;
        char perms[5];
        char path[256] = {0};

        if (sscanf(line, "%lx-%*lx %4s %*x %*x:%*x %*d %255s", &start_addr, perms, path) < 2) continue;
        uintptr_t start = (uintptr_t)start_addr;

        // Skip non-library entries
        if (path[0] == '\0') continue;
        if (strstr(path, ".so") == NULL) continue;
        // Skip our own library
        if (strstr(path, "libnative_hook.so") != NULL) continue;
        // Skip linker
        if (strstr(path, "/linker") != NULL) continue;

        hook_single_lib(start, path);
    }

    fclose(fp);
    return 0;
}
