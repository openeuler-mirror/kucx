/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "debug.h"
#include "log.h"

#include <ucs/sys/sys.h>
#include <sys/wait.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <link.h>
#ifdef HAVE_DETAILED_BACKTRACE
#  if HAVE_LIBIBERTY_H
#    include <libiberty.h>
#elif HAVE_LIBIBERTY_LIBIBERTY_H
#    include <libiberty/libiberty.h>
#  endif
#  include <bfd.h>
#endif /* HAVE_DETAILED_BACKTRACE */


#define UCS_GDB_MAX_ARGS  32
#define BACKTRACE_MAX 64

struct dl_address_search {
    unsigned long            address;
    const char               *filename;
    unsigned long            base;
};

#ifdef HAVE_DETAILED_BACKTRACE

struct backtrace_line {
    unsigned long            address;
    char                     *file;
    char                     *function;
    unsigned                 lineno;
};

struct backtrace_file {
    struct dl_address_search dl;
    bfd                      *abfd;
    asymbol                  **syms;
};

typedef struct backtrace *backtrace_h;
struct backtrace {
    struct backtrace_line    lines[BACKTRACE_MAX];
    int                      size;
    int                      position;
};

struct backtrace_search {
    int                      count;
    struct backtrace_file    *file;
    int                      backoff; /* search the line where the function call
                                         took place, instead of return address */
    struct backtrace_line    *lines;
    int                      max_lines;
};

#endif /* HAVE_DETAILED_BACKTRACE */

#define UCS_SYS_SIGNAME(signame) [SIG ## signame] = #signame
const char *ucs_signal_names[] = {
    [0] = "SIGNAL0",
    UCS_SYS_SIGNAME(HUP),
    UCS_SYS_SIGNAME(INT),
    UCS_SYS_SIGNAME(QUIT),
    UCS_SYS_SIGNAME(ILL),
    UCS_SYS_SIGNAME(TRAP),
    UCS_SYS_SIGNAME(ABRT),
    UCS_SYS_SIGNAME(BUS),
    UCS_SYS_SIGNAME(FPE),
    UCS_SYS_SIGNAME(KILL),
    UCS_SYS_SIGNAME(USR1),
    UCS_SYS_SIGNAME(SEGV),
    UCS_SYS_SIGNAME(USR2),
    UCS_SYS_SIGNAME(PIPE),
    UCS_SYS_SIGNAME(ALRM),
    UCS_SYS_SIGNAME(TERM),
    UCS_SYS_SIGNAME(STKFLT),
    UCS_SYS_SIGNAME(CHLD),
    UCS_SYS_SIGNAME(CONT),
    UCS_SYS_SIGNAME(STOP),
    UCS_SYS_SIGNAME(TSTP),
    UCS_SYS_SIGNAME(TTIN),
    UCS_SYS_SIGNAME(TTOU),
    UCS_SYS_SIGNAME(URG),
    UCS_SYS_SIGNAME(XCPU),
    UCS_SYS_SIGNAME(XFSZ),
    UCS_SYS_SIGNAME(VTALRM),
    UCS_SYS_SIGNAME(PROF),
    UCS_SYS_SIGNAME(WINCH),
    UCS_SYS_SIGNAME(IO),
    UCS_SYS_SIGNAME(PWR),
    UCS_SYS_SIGNAME(SYS),
    [SIGSYS + 1] = NULL
};

static void *ucs_debug_signal_restorer = &ucs_debug_signal_restorer;

static int ucs_debug_backtrace_is_excluded(void *address, const char *symbol);


static int dl_match_address(struct dl_phdr_info *info, size_t size, void *data)
{
    struct dl_address_search *dl = data;
    const ElfW(Phdr) *phdr;
    ElfW(Addr) load_base = info->dlpi_addr;
    long n;

    phdr = info->dlpi_phdr;
    for (n = info->dlpi_phnum; --n >= 0; phdr++) {
        if (phdr->p_type == PT_LOAD) {
            ElfW(Addr) vbaseaddr = phdr->p_vaddr + load_base;
            if (dl->address >= vbaseaddr && dl->address < vbaseaddr + phdr->p_memsz) {
                dl->filename = info->dlpi_name;
                dl->base     = info->dlpi_addr;
            }
        }
    }
    return 0;
}

static int dl_lookup_address(struct dl_address_search *dl)
{
    dl->filename = NULL;
    dl->base     = 0;

    dl_iterate_phdr(dl_match_address, dl);
    if (dl->filename == NULL) {
        return 0;
    }

    if (strlen(dl->filename) == 0) {
        dl->filename = ucs_get_exe();
    }
    return 1;
}

#ifdef HAVE_DETAILED_BACKTRACE

/*
 * The dl member in file should be initialized
 */
static int load_file(struct backtrace_file *file)
{
    long symcount;
    unsigned int size;
    char **matching;

    file->syms = NULL;
    file->abfd = bfd_openr(file->dl.filename, NULL);
    if (!file->abfd) {
        goto err;
    }

    if (bfd_check_format(file->abfd, bfd_archive)) {
        goto err_close;
    }

    if (!bfd_check_format_matches(file->abfd, bfd_object, &matching)) {
        goto err_close;
    }

    if ((bfd_get_file_flags(file->abfd) & HAS_SYMS) == 0) {
        goto err_close;
    }

    symcount = bfd_read_minisymbols(file->abfd, 0, (PTR)&file->syms, &size);
    if (symcount == 0) {
        free(file->syms);
        symcount = bfd_read_minisymbols(file->abfd, 1, (PTR)&file->syms, &size);
    }
    if (symcount < 0) {
        goto err_close;
    }

    return 1;

err_close:
    bfd_close(file->abfd);
err:
    return 0;
}

static void unload_file(struct backtrace_file *file)
{
    free(file->syms);
    bfd_close(file->abfd);
}

static void find_address_in_section(bfd *abfd, asection *section, void *data)
{
    struct backtrace_search *search = data;
    bfd_size_type size;
    bfd_vma vma;
    unsigned long address;
    const char *filename, *function;
    unsigned lineno;
    int found;

    if ((search->count > 0) || (search->max_lines == 0) ||
        ((bfd_get_section_flags(abfd, section) & SEC_ALLOC) == 0)) {
        return;
    }

    address = search->file->dl.address - search->file->dl.base;
    vma = bfd_get_section_vma(abfd, section);
    if (address < vma) {
        return;
    }

    size = bfd_section_size(abfd, section);
    if (address >= vma + size) {
        return;
    }

    /* Search in address-1 to get the calling line instead of return address */
    found = bfd_find_nearest_line(abfd, section, search->file->syms,
                                  address - vma - search->backoff,
                                  &filename, &function, &lineno);
    do {
        search->lines[search->count].address  = address;
        search->lines[search->count].file     = filename ? strdup(filename) : NULL;
        search->lines[search->count].function = function ? strdup(function) : NULL;
        search->lines[search->count].lineno   = lineno;
        if (search->count == 0) {
            /* To get the inliner info, search at the original address */
            bfd_find_nearest_line(abfd, section, search->file->syms, address - vma,
                                  &filename, &function, &lineno);
        }

        ++search->count;
        found = bfd_find_inliner_info(abfd, &filename, &function, &lineno);
    } while (found && (search->count < search->max_lines));
}

static int get_line_info(struct backtrace_file *file, int backoff,
                         struct backtrace_line *lines, int max)
{
    struct backtrace_search search;

    search.file      = file;
    search.backoff   = backoff;
    search.count     = 0;
    search.lines     = lines;
    search.max_lines = max;
    bfd_map_over_sections(file->abfd, find_address_in_section, &search);
    return search.count;
}

/**
 * Create a backtrace from the calling location.
 *
 * @return             Backtrace object.
 */
static backtrace_h ucs_debug_backtrace_create(void)
{
    struct backtrace_file file;
    void *addresses[BACKTRACE_MAX];
    int i, num_addresses;
    backtrace_h bckt;

    bckt = malloc(sizeof *bckt);
    if (!bckt) {
        return NULL;
    }

    num_addresses = backtrace(addresses, BACKTRACE_MAX);

    bckt->size = 0;
    for (i = 0; i < num_addresses; ++i) {
        file.dl.address = (unsigned long)addresses[i];
        if (dl_lookup_address(&file.dl) && load_file(&file)) {
            bckt->size += get_line_info(&file, 1, bckt->lines + bckt->size,
                                        BACKTRACE_MAX - bckt->size);
            unload_file(&file);
        }
    }

    bckt->position = 0;
    return bckt;
}

/**
 * Destroy a backtrace and free all memory.
 *
 * @param bckt          Backtrace object.
 */
static void ucs_debug_backtrace_destroy(backtrace_h bckt)
{
    int i;

    for (i = 0; i < bckt->size; ++i) {
        free(bckt->lines[i].function);
        free(bckt->lines[i].file);
    }
    free(bckt);
}

void ucs_debug_get_line_info(const char *filename, unsigned long base,
                             unsigned long address, ucs_debug_address_info_t *info)
{
    struct backtrace_file file;
    struct backtrace_line line;
    int count;

    file.dl.filename = filename;
    file.dl.base     = base;
    file.dl.address  = address;

    if (!load_file(&file)) {
        goto err;
    }

    count = get_line_info(&file, 0, &line, 1);
    if (count == 0) {
        goto err_unload;
    }

    if (line.function) {
        strncpy(info->function, line.function, sizeof(info->function));
    } else {
        strcpy(info->function, "???");
    }
    if (line.file) {
        strncpy(info->source_file, line.file, sizeof(info->source_file));
    } else {
        strcpy(info->function, "???");
    }
    info->line_number = line.lineno;

    free(line.function);
    free(line.file);
    unload_file(&file);
    return;

err_unload:
    unload_file(&file);
err:
    strcpy(info->function, "");
    strcpy(info->source_file, "");
    info->line_number = 0;
}

/**
 * Walk to the next backtrace line information.
 *
 * @param bckt          Backtrace object.
 * @param address       Filled with backtrace address.
 * @param file          Filled with a pointer to the source file name.
 * @param function      Filled with a pointer to function name.
 * @param lineno        Filled with source line number.
 *
 * NOTE: the file and function memory remains valid as long as the backtrace
 * object is not destroyed.
 */
int backtrace_next(backtrace_h bckt, unsigned long *address, char const ** file,
                   char const ** function, unsigned *lineno)
{
    struct backtrace_line *line;

    if (bckt->position >= bckt->size)
        return 0;

    line = &bckt->lines[bckt->position++];
    *address = line->address;
    *file = line->file;
    *function = line->function;
    *lineno = line->lineno;
    return 1;
}

/*
 * Filter specific functions from the head of the backtrace.
 */
void ucs_debug_print_backtrace(FILE *stream, int strip)
{
    backtrace_h bckt;
    unsigned long address;
    const char *file, *function;
    unsigned line;
    int exclude;
    int i, n;

    bckt = ucs_debug_backtrace_create();

    fprintf(stream, "==== backtrace ====\n");
    exclude = 1;
    i       = 0;
    n       = 0;
    while (backtrace_next(bckt, &address, &file, &function, &line)) {
        if (i >= strip) {
            exclude = exclude && ucs_debug_backtrace_is_excluded((void*)address,
                                                                 function);
            if (!exclude) {
                fprintf(stream, "%2d 0x%016lx %s()  %s:%u\n", n, address,
                        function ? function : "??", file ? file : "??", line);
                ++n;
            }
        }
        ++i;
    }
    fprintf(stream, "===================\n");

    ucs_debug_backtrace_destroy(bckt);
}

const char *ucs_debug_get_symbol_name(void *address, char *buffer, size_t max)
{
    ucs_debug_address_info_t info;
    ucs_debug_lookup_address(address, &info);
    return strncpy(buffer, info.function, max);
}

static void ucs_debug_print_source_file(const char *file, unsigned line,
                                        const char *function, FILE *stream)
{
    static const int context = 3;
    char srcline[256];
    unsigned n;
    FILE *f;

    f = fopen(file, "r");
    if (f == NULL) {
        return;
    }

    n = 0;
    fprintf(stream, "\n");
    fprintf(stream, "%s: [ %s() ]\n", file, function);
    if (line > context) {
        fprintf(stream, "      ...\n");
    }
    while (fgets(srcline, sizeof(srcline), f) != NULL) {
        if (abs((int)line - (int)n) <= context) {
            fprintf(stream, "%s %5u %s",
                    (n == line) ? "==>" : "   ", n, srcline);
        }
        ++n;
    }
    fprintf(stream, "\n");

    fclose(f);
}

static void ucs_debug_show_innermost_source_file(FILE *stream)
{
    const char *file, *function;
    unsigned long address;
    backtrace_h bckt;
    unsigned line;

    bckt = ucs_debug_backtrace_create();
    while (backtrace_next(bckt, &address, &file, &function, &line)) {
        if (!ucs_debug_backtrace_is_excluded((void*)address, function)) {
            ucs_debug_print_source_file(file, line, function, stderr);
            break;
        }
    }
    ucs_debug_backtrace_destroy(bckt);
}

#else /* HAVE_DETAILED_BACKTRACE */

void ucs_debug_get_line_info(const char *filename, unsigned long base, unsigned long address,
                             ucs_debug_address_info_t *info)
{
    strcpy(info->function, "");
    strcpy(info->source_file, "");
    info->line_number = 0;
}

void ucs_debug_print_backtrace(FILE *stream, int strip)
{
    char **symbols;
    void *addresses[BACKTRACE_MAX];
    int count, i, n;

    fprintf(stream, "==== backtrace ====\n");

    count = backtrace(addresses, BACKTRACE_MAX);
    symbols = backtrace_symbols(addresses, count);
    n = 0;
    for (i = strip; i < count; ++i) {
        if (!ucs_debug_backtrace_is_excluded(addresses[i], symbols[i])) {
            fprintf(stream, "   %2d  %s\n", n, symbols[i]);
            ++n;
        }
    }
    free(symbols);

    fprintf(stream, "===================\n");
}

const char *ucs_debug_get_symbol_name(void *address, char *buffer, size_t max)
{
    Dl_info info;
    int ret;

    ret = dladdr(address, &info);
    if (ret != 0) {
        return NULL;
    }

    return strncpy(buffer, info.dli_sname, max);
}

static void ucs_debug_show_innermost_source_file(FILE *stream)
{
}

#endif /* HAVE_DETAILED_BACKTRACE */

static ucs_status_t ucs_debugger_attach()
{
    static const char *gdb_commands = "bt\n";
    const char *cmds;
    char *gdb_cmdline;
    char gdb_commands_file[256];
    char* argv[6 + UCS_GDB_MAX_ARGS];
    pid_t pid, debug_pid;
    int fd, ret, narg;
    int valgrind;
    char *self_exe;

    debug_pid = getpid();

    /* Fork a process which will execute gdb */
    pid = fork();
    if (pid < 0) {
        ucs_log_fatal_error("fork returned %d: %m", pid);
        return UCS_ERR_IO_ERROR;
    }

    valgrind = RUNNING_ON_VALGRIND;
    self_exe = strdup(ucs_get_exe());

    if (pid == 0) {
        gdb_cmdline = strdup(ucs_global_opts.gdb_command);
        narg = 0;
        argv[narg] = strtok(gdb_cmdline, " \t");
        while (argv[narg] != NULL) {
            ++narg;
            argv[narg] = strtok(NULL, " \t");
        }

        if (!valgrind) {
            argv[narg++] = "-p";
            if (asprintf(&argv[narg++], "%d", debug_pid)<0) {
                ucs_log_fatal_error("Failed to extract pid : %m");
                exit(-1);
            }
        }

        /* Generate a file name for gdb commands */
        memset(gdb_commands_file, 0, sizeof(gdb_commands_file));
        snprintf(gdb_commands_file, sizeof(gdb_commands_file) - 1,
                 "/tmp/.gdbcommands.%s", getlogin());

        /* Write gdb commands and add the file to argv is successful */
        fd = open(gdb_commands_file, O_WRONLY|O_TRUNC|O_CREAT, 0600);
        if (fd >= 0) {
            if (valgrind) {
                if (asprintf((char**)&cmds, "file %s\n"
                                            "target remote | vgdb\n"
                                            "%s",
                                            self_exe, gdb_commands) < 0) {
                    cmds = "";
                }
            } else {
                cmds = gdb_commands;
            }

            if (write(fd, cmds, strlen(cmds)) == strlen(cmds)) {
                argv[narg++] = "-x";
                argv[narg++] = gdb_commands_file;
            } else {
                ucs_log_fatal_error("Unable to write to command file: %m");
            }
            close(fd);
        } else {
            ucs_log_fatal_error("Unable to open '%s' for writing: %m",
                                gdb_commands_file);
        }

        argv[narg++] = NULL;

        /* Execute GDB */
        ret = execvp(argv[0], argv);
        if (ret < 0) {
            ucs_log_fatal_error("Failed to execute %s: %m", argv[0]);
            exit(-1);
        }
    }

    free(self_exe);
    waitpid(pid, &ret, 0);
    return UCS_OK;
}

static void UCS_F_NOINLINE ucs_debug_freeze()
{
    static volatile int freeze = 1;
    while (freeze) {
        pause();
    }
}

static int ucs_debug_stop_exclude_thread = -1;
static void ucs_debug_stop_handler(int signo)
{
    if (ucs_get_tid() == ucs_debug_stop_exclude_thread) {
        return;
    }

    ucs_debug_freeze();
}

static void ucs_debug_stop_other_threads()
{
    ucs_debug_stop_exclude_thread = ucs_get_tid();
    signal(SIGUSR1, ucs_debug_stop_handler);
    kill(0, SIGUSR1);
}

static ucs_status_t ucs_error_freeze()
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    char response;
    int ret;

    ucs_debug_stop_other_threads();
    ucs_debug_show_innermost_source_file(stderr);

    if (pthread_mutex_trylock(&lock) == 0) {
        if (strlen(ucs_global_opts.gdb_command) && isatty(fileno(stdout)) &&
            isatty(fileno(stdin)))
        {
            ucs_log_fatal_error("Process frozen, press Enter to attach a debugger...");
            ret = read(fileno(stdin), &response, 1); /* Use low-level input to avoid deadlock */
            if ((ret == 1) && (response == '\n')) {
                ucs_debugger_attach();
            } else {
                ucs_debug_freeze();
            }
        } else {
            ucs_log_fatal_error("Process frozen...");
            ucs_debug_freeze();
        }

        pthread_mutex_unlock(&lock);
    } else {
        ucs_debug_freeze();
    }

    return UCS_OK;
}

static const char *ucs_signal_cause_common(int si_code)
{
    switch (si_code) {
    case SI_USER      : return "kill(2) or raise(3)";
    case SI_KERNEL    : return "Sent by the kernel";
    case SI_QUEUE     : return "sigqueue(2)";
    case SI_TIMER     : return "POSIX timer expired";
    case SI_MESGQ     : return "POSIX message queue state changed";
    case SI_ASYNCIO   : return "AIO completed";
    case SI_SIGIO     : return "queued SIGIO";
    case SI_TKILL     : return "tkill(2) or tgkill(2)";
    default           : return "<unknown si_code>";
    }
}

static const char *ucs_signal_cause_ill(int si_code)
{
    switch (si_code) {
    case ILL_ILLOPC   : return "illegal opcode";
    case ILL_ILLOPN   : return "illegal operand";
    case ILL_ILLADR   : return "illegal addressing mode";
    case ILL_ILLTRP   : return "illegal trap";
    case ILL_PRVOPC   : return "privileged opcode";
    case ILL_PRVREG   : return "privileged register";
    case ILL_COPROC   : return "coprocessor error";
    case ILL_BADSTK   : return "internal stack error";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_fpe(int si_code)
{
    switch (si_code) {
    case FPE_INTDIV   : return "integer divide by zero";
    case FPE_INTOVF   : return "integer overflow";
    case FPE_FLTDIV   : return "floating-point divide by zero";
    case FPE_FLTOVF   : return "floating-point overflow";
    case FPE_FLTUND   : return "floating-point underflow";
    case FPE_FLTRES   : return "floating-point inexact result";
    case FPE_FLTINV   : return "floating-point invalid operation";
    case FPE_FLTSUB   : return "subscript out of range";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_segv(int si_code)
{
    switch (si_code) {
    case SEGV_MAPERR  : return "address not mapped to object";
    case SEGV_ACCERR  : return "invalid permissions for mapped object";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_bus(int si_code)
{
    switch (si_code) {
    case BUS_ADRERR   : return "nonexistent physical address";
    case BUS_OBJERR   : return "object-specific hardware error";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_trap(int si_code)
{
    switch (si_code) {
    case TRAP_BRKPT   : return "process breakpoint";
    case TRAP_TRACE   : return "process trace trap";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_cld(int si_code)
{
    switch (si_code) {
    case CLD_EXITED   : return "child has exited";
    case CLD_KILLED   : return "child was killed";
    case CLD_DUMPED   : return "child terminated abnormally";
    case CLD_TRAPPED  : return "traced child has trapped";
    case CLD_STOPPED  : return "child has stopped";
    case CLD_CONTINUED: return "stopped child has continued";
    default           : return NULL;
    }
}

static void ucs_debug_log_signal(int signo, const char *cause, const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    ucs_log_fatal_error("Caught signal %d (%s: %s%s)", signo, strsignal(signo),
                        cause, buf);
}

static void ucs_error_signal_handler(int signo, siginfo_t *info, void *context)
{
    ucs_debug_cleanup();
    ucs_log_flush();

    switch (signo) {
    case SIGILL:
        ucs_debug_log_signal(signo, ucs_signal_cause_ill(info->si_code), "");
        break;
    case SIGTRAP:
        ucs_debug_log_signal(signo, ucs_signal_cause_trap(info->si_code), "");
        break;
    case SIGBUS:
        ucs_debug_log_signal(signo, ucs_signal_cause_bus(info->si_code), "");
        break;
    case SIGFPE:
        ucs_debug_log_signal(signo, ucs_signal_cause_fpe(info->si_code), "");
        break;
    case SIGSEGV:
        ucs_debug_log_signal(signo, ucs_signal_cause_segv(info->si_code),
                             " at address %p", info->si_addr);
        break;
    case SIGCHLD:
        ucs_debug_log_signal(signo, ucs_signal_cause_cld(info->si_code), "");
        break;
    default:
        ucs_debug_log_signal(signo, ucs_signal_cause_common(info->si_code), "");
        break;
    }

    if (signo != SIGINT && signo != SIGTERM) {
        ucs_handle_error();
    }
    raise(signo);
}

void ucs_handle_error()
{
    ucs_status_t status;

    switch (ucs_global_opts.handle_errors) {
    case UCS_HANDLE_ERROR_DEBUG:
        status = ucs_debugger_attach();
        if (status == UCS_OK) {
            break;
        }
        /* Fall thru */

    case UCS_HANDLE_ERROR_FREEZE:
        status = ucs_error_freeze();
        if (status == UCS_OK) {
            break;
        }
        /* Fall thru */

    case UCS_HANDLE_ERROR_BACKTRACE:
        ucs_debug_show_innermost_source_file(stderr);
        ucs_debug_print_backtrace(stderr, 2);
        break;

    default:
        break;
    }
}

static void ucs_debug_signal_handler(int signo)
{
    ucs_log_flush();

    ucs_log_fatal_error("Got debug signal, raising log level",
                        ucs_get_host_name(), getpid());
    ucs_global_opts.log_level = UCS_LOG_LEVEL_TRACE_DATA;
}

static void ucs_set_signal_handler(void (*handler)(int, siginfo_t*, void *))
{
    struct sigaction sigact, old_action;
    int i;

    if (handler == NULL) {
        sigact.sa_handler   = SIG_DFL;
        sigact.sa_flags     = 0;
    } else {
        sigact.sa_sigaction = handler;
        sigact.sa_flags     = SA_SIGINFO;
    }
    sigemptyset(&sigact.sa_mask);

    for (i = 0; i < ucs_global_opts.error_signals.count; ++i) {
        sigaction(ucs_global_opts.error_signals.signals[i], &sigact, &old_action);
        ucs_debug_signal_restorer = old_action.sa_restorer;
    }
}

static int ucs_debug_backtrace_is_excluded(void *address, const char *symbol)
{
    return !strcmp(symbol, "ucs_handle_error") ||
           !strcmp(symbol, "ucs_error_freeze") ||
           !strcmp(symbol, "ucs_error_signal_handler") ||
           !strcmp(symbol, "ucs_debug_backtrace_create") ||
           !strcmp(symbol, "ucs_debug_show_innermost_source_file") ||
           !strcmp(symbol, "__ucs_abort") ||
           (address == ucs_debug_signal_restorer);
}

ucs_status_t ucs_debug_lookup_address(void *address, ucs_debug_address_info_t *info)
{
    struct dl_address_search dl;

    dl.address = (unsigned long)address;
    if (!dl_lookup_address(&dl)) {
        return UCS_ERR_NO_ELEM;
    }

    memset(info, 0, sizeof(*info));
    info->file.base = dl.base;
    ucs_expand_path(dl.filename, info->file.path, sizeof(info->file.path));

    ucs_debug_get_line_info(dl.filename, dl.base, (unsigned long)address, info);
    return UCS_OK;
}

static struct dl_address_search *ucs_debug_get_lib_info()
{
    static struct dl_address_search dl = {0, NULL, 0};

    if (dl.address == 0) {
        dl.address = (unsigned long)&ucs_debug_get_lib_info;
        if (!dl_lookup_address(&dl)) {
            dl.filename = NULL;
            dl.base     = 0;
        }
    }

    /* If we failed to look up the address, return NULL */
    return (dl.filename == NULL || dl.base == 0) ? NULL : &dl;
}

const char *ucs_debug_get_lib_path()
{
    static char ucs_lib_path[256] = {0};
    struct dl_address_search *dl;

    if (!strlen(ucs_lib_path)) {
        dl = ucs_debug_get_lib_info();
        if (dl != NULL) {
            ucs_expand_path(dl->filename, ucs_lib_path, sizeof(ucs_lib_path));
        }
    }

    return ucs_lib_path;
}

unsigned long ucs_debug_get_lib_base_addr()
{
    struct dl_address_search *dl = ucs_debug_get_lib_info();
    return (dl == NULL) ? 0 : dl->base;
}

void ucs_debug_init()
{
    if (ucs_global_opts.handle_errors > UCS_HANDLE_ERROR_NONE) {
        ucs_set_signal_handler(ucs_error_signal_handler);
    }
    if (ucs_global_opts.debug_signo > 0) {
        signal(ucs_global_opts.debug_signo, ucs_debug_signal_handler);
    }

#ifdef HAVE_DETAILED_BACKTRACE
    bfd_init();
#endif
}

void ucs_debug_cleanup()
{
    if (ucs_global_opts.handle_errors > UCS_HANDLE_ERROR_NONE) {
        ucs_set_signal_handler(NULL);
    }
    if (ucs_global_opts.debug_signo > 0) {
        signal(ucs_global_opts.debug_signo, SIG_DFL);
    }
}
