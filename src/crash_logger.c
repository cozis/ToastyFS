#if defined(__linux__) && defined(__x86_64__)

#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <ucontext.h>

typedef struct {
    uint64_t base_addr;
    int count;
    void *symbols;
    void *strings;
} SymbolTable;

static int is_hex(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static uint64_t query_base_addr(void)
{
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return -1;

    char buf[128];
    int ret = read(fd, buf, sizeof(buf));
    if (ret < 0) {
        close(fd);
        return -1;
    }

    close(fd);

    if (ret == 0 || !is_hex(buf[0]))
        return -1;

    int i = 0;
    uint64_t base_addr = 0;
    for (;;) {
        char c = buf[i++];

        int d;
        if (0) {}
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else d = c - '0';

        if (base_addr > (UINT64_MAX - d) / 16)
            return -1;
        base_addr = base_addr * 16 + d;

        if (i == ret)
            return -1;

        if (buf[i] == '-')
            break;

        if (!is_hex(buf[i]))
            return -1;
    }

    return base_addr;
}

static int current_executable_path(char *dst, int cap)
{
    if (cap == 0)
        return -1;

    int ret = readlink("/proc/self/exe", dst, cap-1);
    if (ret < 0)
        return -1;
    dst[ret] = '\0';
    return ret;
}

static int load_symbols_from_elf(void *src, int len, SymbolTable *st)
{
    // NOTE: It's assumed is properly aligned
    assert(((uintptr_t) src & 15) == 0);

    // Check that the file contains a full header
    if (len < (int) sizeof(Elf64_Ehdr))
        return -1;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*) src;

    // Check that the file contains the full list
    // of section headers
    if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > len)
        return -1;
    Elf64_Shdr *shdrs = (Elf64_Shdr*) (src + ehdr->e_shoff);

    Elf64_Shdr *shstrtab_hdr = &shdrs[ehdr->e_shstrndx]; // TODO: bounds check
    char *shstrtab = src + shstrtab_hdr->sh_offset;

    // Iterate over the section headers to find the
    // one reative to symbols and their strings
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *section_name = shstrtab + shdrs[i].sh_name;
        if (0) {}
        else if (!strcmp(section_name, ".symtab")) symtab_hdr = &shdrs[i];
        else if (!strcmp(section_name, ".strtab")) strtab_hdr = &shdrs[i];
    }

    if (symtab_hdr == NULL || strtab_hdr == NULL) {
        return -1;
    }

    void *mem = malloc(symtab_hdr->sh_size + strtab_hdr->sh_size);
    if (mem == NULL) {
        return -1;
    }

    st->count = symtab_hdr->sh_size / sizeof(Elf64_Sym);
    st->symbols = mem;
    st->strings = (char*) st->symbols + symtab_hdr->sh_size;

    memcpy(st->symbols, src + symtab_hdr->sh_offset, symtab_hdr->sh_size);
    memcpy(st->strings, src + strtab_hdr->sh_offset, strtab_hdr->sh_size);

    return 0;
}

static char *read_file(char *path, int *len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat buf;
    if (fstat(fd, &buf) < 0) {
        close(fd);
        return NULL;
    }
    *len = buf.st_size;

    char *ptr = malloc(*len + 1);
    if (ptr == NULL) {
        close(fd);
        return NULL;
    }

    for (int num = 0; num < *len; ) {

        int ret = read(fd, ptr + num, *len - num);
        if (ret <= 0) {
            free(ptr);
            close(fd);
            return NULL;
        }

        num += ret;
    }

    ptr[*len] = '\0';
    return ptr;
}

static int symbol_table_from_current_process(SymbolTable *st)
{
    uint64_t base_addr = query_base_addr();
    if (base_addr == (uint64_t) -1)
        return -1;
    st->base_addr = base_addr;

    char path[1<<10];
    if (current_executable_path(path, sizeof(path)) < 0)
        return -1;

    char *exe_ptr;
    int   exe_len;
    exe_ptr = read_file(path, &exe_len);
    if (exe_ptr == NULL)
        return -1;

    if (load_symbols_from_elf(exe_ptr, exe_len, st) < 0) {
        free(exe_ptr);
        return -1;
    }

    free(exe_ptr);
    return 0;
}

static void symbol_table_free(SymbolTable *st)
{
    free(st->symbols);
}

static char *symbol_table_find(SymbolTable *st, uint64_t addr)
{
    for (int i = 0; i < st->count; i++) {
        Elf64_Sym *sym = (Elf64_Sym*) st->symbols + i;

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        if (sym->st_value == 0)
            continue;

        uint64_t sym_beg = st->base_addr + sym->st_value;
        uint64_t sym_end = st->base_addr + sym->st_value + sym->st_size;

        if (addr >= sym_beg && addr < sym_end)
            return (char*) st->strings + sym->st_name;
    }

    return NULL;
}

#if 0
static void symbol_table_dump(SymbolTable *st)
{
    for (int i = 0; i < st->count; i++) {
        Elf64_Sym *sym = (Elf64_Sym*) st->symbols + i;

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        if (sym->st_value == 0)
            continue;

        char *name = (char*) st->strings + sym->st_name;
        printf("%s\n", name);
    }
}
#endif

typedef struct {
    char    *name;
    uint64_t addr;
} StackFrame;

static int walk_stack(uint64_t rip, uint64_t rbp, SymbolTable *st, StackFrame *frames, int max_frames)
{
    int frame_count = 0;

    if (frame_count < max_frames) {
        frames[frame_count].addr = rip - st->base_addr;
        frames[frame_count].name = symbol_table_find(st, rip);
        frame_count++;
    }

    while (rbp != 0) {

        if (rbp & 0xF)
            break;

        uint64_t *frame_ptr = (uint64_t*) rbp;

        uint64_t next_rbp    = frame_ptr[0];
        uint64_t return_addr = frame_ptr[1];

        if (next_rbp != 0 && next_rbp <= rbp)
            break;

        if (return_addr == 0)
            break;

        if (frame_count == max_frames)
            break;
        frames[frame_count].addr = return_addr - st->base_addr;
        frames[frame_count].name = symbol_table_find(st, return_addr);
        frame_count++;

        rbp = next_rbp;
    }

    return frame_count;
}

static bool        crash_logger_symbol_init = false;
static char*       crash_logger_file_name = NULL;
static SymbolTable crash_logger_symbol_table;
static char*       crash_logger_signal_stack;

static void crash_handler(int sig, siginfo_t *info, void *ucontext)
{
    (void) info;

    if (crash_logger_symbol_init) {

        // Buffer for evaluating format strings
        char tmp[1<<9];
        int len;

        ucontext_t *ctx = (ucontext_t*) ucontext;
        uint64_t rip = ctx->uc_mcontext.gregs[REG_RIP];
        uint64_t rbp = ctx->uc_mcontext.gregs[REG_RBP];

        StackFrame frames[64];
        int count = walk_stack(rip, rbp, &crash_logger_symbol_table, frames, 64);

        int fd = open(crash_logger_file_name, O_WRONLY | O_CREAT, 0666);
        if (fd < 0)
            exit(1);

        char *sig_name = "";
        switch (sig) {
            case SIGSEGV: sig_name = "Segmentation fault";       break;
            case SIGBUS : sig_name = "Bus error";                break;
            case SIGILL : sig_name = "Illegal instruction";      break;
            case SIGFPE : sig_name = "Floating point exception"; break;
            case SIGTRAP: sig_name = "Trace trap";               break;
            case SIGSYS : sig_name = "Bad system call";          break;
            case SIGABRT: sig_name = "Abort";                    break;
        }
        if (sig_name[0] == '\0') {
            len = snprintf(tmp, sizeof(tmp), "(unknown signal %d)\n", sig);
            write(fd, tmp, len);
        } else {
            write(fd, sig_name, strlen(sig_name));
            write(fd, "\n", 1);
        }

        for (int i = 0; i < count; i++) {
            len = snprintf(tmp, sizeof(tmp), "  [%d] 0x%lx %s\n", i, frames[i].addr,
                frames[i].name ? frames[i].name : "?");
            write(fd, tmp, len);
        }

        close(fd);
    }
    exit(1);
}

int crash_logger_init(char *file_name, int file_name_len)
{
    {
        char *file_name_copy = malloc(file_name_len + 1);
        if (file_name_copy == NULL)
            return -1;
        memcpy(file_name_copy, file_name, file_name_len);
        file_name_copy[file_name_len] = '\0';
        crash_logger_file_name = file_name_copy;
    }

    if (symbol_table_from_current_process(&crash_logger_symbol_table) < 0) {
        free(crash_logger_file_name);
        return -1;
    }

    // Set up alternate signal stack
    {
        crash_logger_signal_stack = malloc(SIGSTKSZ);
        if (crash_logger_signal_stack == NULL) {
            symbol_table_free(&crash_logger_symbol_table);
            free(crash_logger_file_name);
            return -1;
        }

        stack_t ss;
        ss.ss_sp = crash_logger_signal_stack;
        ss.ss_size = SIGSTKSZ;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) < 0) {
            free(crash_logger_signal_stack);
            symbol_table_free(&crash_logger_symbol_table);
            free(crash_logger_file_name);
            return -1;
        }
    }

    {
        // Register the crash handler
        struct sigaction sa;
        sa.sa_sigaction = crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;  // Add SA_ONSTACK flag
        sigemptyset(&sa.sa_mask);

        // Memory errors
        sigaction(SIGSEGV, &sa, NULL);  // Segmentation fault (invalid memory access)
        sigaction(SIGBUS, &sa, NULL);   // Bus error (misaligned access, hardware error)

        // Execution errors
        sigaction(SIGILL, &sa, NULL);   // Illegal instruction
        sigaction(SIGFPE, &sa, NULL);   // Floating point exception
        sigaction(SIGTRAP, &sa, NULL);  // Trace trap

        // System/resource errors
        sigaction(SIGSYS, &sa, NULL);   // Bad system call
        sigaction(SIGABRT, &sa, NULL);  // Abort (from assert, abort(), etc.)

        // Optional: Resource limit violations
        sigaction(SIGXCPU, &sa, NULL);  // CPU time limit exceeded
        sigaction(SIGXFSZ, &sa, NULL);  // File size limit exceeded
    }

    crash_logger_symbol_init = true;
    return 0;
}

void crash_logger_free(void)
{
    if (!crash_logger_symbol_init)
        return;

    free(crash_logger_signal_stack);
    symbol_table_free(&crash_logger_symbol_table);
    free(crash_logger_file_name);

    crash_logger_symbol_init = false;
}

#else

static int crash_logger_init(char *file_name, int file_name_len)
{
    (void) file_name;
    (void) file_name_len;
    return -1;
}

static void crash_logger_free(void)
{
}

#endif
