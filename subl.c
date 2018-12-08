#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

#include <fcntl.h>
//#include <linux/seccomp.h>
#define SECCOMP_MODE_FILTER 2
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define eprintf(format, ...)                             \
    fprintf(stderr, "\x1b[3%dm[%s:%d(%s)]\x1b[m" format, \
        __LINE__ % 6 + 1, __FILE__, __LINE__,            \
        __PRETTY_FUNCTION__, ##__VA_ARGS__)

typedef long long ll;
typedef unsigned long long ull;

// seccomp-tools
// https://github.com/david942j/seccomp-tools
static const unsigned char filter[] = { 32, 0, 0, 0, 4, 0, 0, 0, 21, 0, 0, 13, 62, 0, 0, 192, 32, 0, 0, 0, 0, 0, 0, 0, 53, 0, 11, 0, 0, 0, 0, 64, 21, 0, 9, 0, 0, 0, 0, 0, 21, 0, 8, 0, 1, 0, 0, 0, 21, 0, 7, 0, 19, 0, 0, 0, 21, 0, 6, 0, 20, 0, 0, 0, 21, 0, 5, 0, 96, 0, 0, 0, 21, 0, 4, 0, 228, 0, 0, 0, 21, 0, 3, 0, 60, 0, 0, 0, 21, 0, 2, 0, 231, 0, 0, 0, 21, 0, 1, 0, 35, 0, 0, 0, 6, 0, 0, 0, 38, 0, 5, 0, 6, 0, 0, 0, 0, 0, 255, 127, 6, 0, 0, 0, 0, 0, 0, 0 };

#define EXIT_ON_FAIL_HINT(EXPR, HINT)                     \
    if (EXPR) {                                           \
        perror(HINT);                                     \
        eprintf(#EXPR " returned with nonzero status\n"); \
        exit(-1);                                         \
    }
#define WARN_ON_FAIL_HINT(EXPR, HINT)                     \
    if (EXPR) {                                           \
        perror(HINT);                                     \
        eprintf(#EXPR " returned with nonzero status\n"); \
    }

#define EXIT_ON_FAIL(EXPR) EXIT_ON_FAIL_HINT(EXPR, #EXPR)
#define WARN_ON_FAIL(EXPR) WARN_ON_FAIL_HINT(EXPR, #EXPR)
#define FLAG_ADDR ((void*)0x555000)

typedef enum { false,
    true } bool;

typedef uint32_t WD;

//extern WD binary[0x4000];

static WD* emu_mem;

static const char* rom;
static void* rom_content;
static int romsz;
static const char* flag; // both filename and flag content
static int rand_fd;
static char random_buffer[0x1000];
static int used;

static void get_random(void* dest, ssize_t size)
{
    // hand written random reading
    int cur_used = used & 0xfff;
    if (size > 0x1000 - used) {
        if (cur_used) {
            read(rand_fd, random_buffer, cur_used);
            cur_used = 0;
        }
        read(rand_fd, dest, size);
    } else {
        memcpy(dest, random_buffer + used, size);
        cur_used += size;
        if (cur_used == 0x1000) {
            read(rand_fd, random_buffer, 0x1000);
            cur_used = 0;
        }
    }
    used = cur_used;
}

static void init_random_fd(void)
{
    // random buffer
    rand_fd = open("/dev/urandom", O_RDONLY);
    EXIT_ON_FAIL(rand_fd < 0);
    read(rand_fd, random_buffer, 4096);
}

static void init_flag(void)
{
    // flag
    void* flag_addr = NULL;
    if (flag) {
        int flag_fd = open(flag, O_RDONLY);
        EXIT_ON_FAIL(flag_fd < 0);
        flag_addr = mmap(FLAG_ADDR, 0x1000, PROT_READ, MAP_PRIVATE, flag_fd, 0);
        EXIT_ON_FAIL(flag_addr == MAP_FAILED);
        close(flag_fd);
    } else {
        flag_addr = "";
    }
    flag = (const char*)flag_addr;
}

static off_t getsz(int fd)
{
    struct stat st;
    EXIT_ON_FAIL(fstat(fd, &st) < 0);
    return st.st_size;
}

static void init_rom(void)
{
    // rom
    int rom_fd = open(rom, O_RDONLY);
    EXIT_ON_FAIL(rom_fd < 0);
    // we assume no one race us here ...
    // we also assume that rom sz is smaller than some arbitrary limit
    int rom_fsz = getsz(rom_fd) & 0xffffff;
    if (rom_fsz & 0xfff) {
        rom_fsz = (rom_fsz & -0x1000) + 0x1000;
    }
    // we can allocate at most 0x100000 for code+data, sadly
    EXIT_ON_FAIL(rom_fsz > 0x100000);
    void* rom_addr = mmap(NULL, rom_fsz, PROT_READ, MAP_PRIVATE, rom_fd, 0);
    EXIT_ON_FAIL(rom_addr == MAP_FAILED);
    close(rom_fd);
    rom_content = rom_addr;
    romsz = rom_fsz;
    rom = NULL;
}

static void init_vmmem(void)
{
    // map vm memory before prctl
    void* vm_mem = mmap(NULL, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EXIT_ON_FAIL(vm_mem == MAP_FAILED);
    emu_mem = (WD*)vm_mem;
}

static void init_fds(void)
{
    init_random_fd();
    init_flag();
    init_rom();
    init_vmmem();
}

static void init_env(void)
{
    // normal prctl protection
    EXIT_ON_FAIL(prctl(PR_SET_DUMPABLE, 0) < 0);
    EXIT_ON_FAIL(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0);
    alarm(90);
    struct rlimit rlim;
    // don't check error, since there may be certain limit set up
    rlim.rlim_cur = rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
    // cputime limit
    rlim.rlim_cur = rlim.rlim_max = 1;
    setrlimit(RLIMIT_CPU, &rlim);
    // vm limit, 16M is more than reasonable (?)
    rlim.rlim_cur = rlim.rlim_max = 0x1000000;
    setrlimit(RLIMIT_AS, &rlim);
    // forkbomb guard
    //rlim.rlim_cur = rlim.rlim_max = 256;
    //setrlimit(RLIMIT_NPROC, &rlim);
    init_fds();
    struct prog {
        unsigned short len;
        const unsigned char* filter;
    } rule = {
        .len = sizeof(filter) >> 3,
        .filter = filter
    };
    EXIT_ON_FAIL(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0);
}

static const WD inv_list[32] = { 1,
    2863311531,
    3435973837,
    3067833783,
    954437177,
    3123612579,
    3303820997,
    4008636143,
    4042322161,
    678152731,
    1022611261,
    3921491879,
    3264175145,
    1749801491,
    1332920885,
    3186588639,
    1041204193,
    2331553675,
    2437684141,
    2532929431,
    3247414297,
    799063683,
    2767867813,
    1736263375,
    438261969,
    4210752251,
    2350076445,
    1483715975,
    3089362441,
    2693454067,
    3238827797,
    3204181951 };

static WD rand_integer(void)
{
    WD ret;
    get_random(&ret, sizeof(ret));
    return ret;
}

// subl devices

static void sl_halt(WD code)
{
    fprintf(stderr, "Program exited with status %u\n", code);
    exit(code);
}

static WD sl_randint(void)
{
    return rand_integer();
}

static WD sl_gettime(void)
{
    struct timeval tv = {};
    int ret = gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void sl_sleep(WD time)
{
    fflush(stdout);
    usleep((long)time * 1000);
}

static void sl_putchar(WD c)
{
    putchar(c);
}

static WD sl_getchar(void)
{
    fflush(stdout);
    static int bad_get = 0;
    int c = getchar();
    if (c == EOF) {
        if (!bad_get) {
            bad_get = 1 + (rand_integer() & 0xf0);
        }
        bad_get++;
        if (bad_get > 256) {
            puts("Broken Pipe");
            exit(-32);
        }
    }
    return c;
}

struct control_block {
    WD* memory;
    union {
        WD flag[20];
        char flag_text[80];
    };
    WD flag_key;
    WD pc;
    WD cycle;
    WD jcycle;
    WD memstat;
};

static void init_cb(struct control_block* cb)
{
    cb->memory = emu_mem; // since we only have one buffer
    int flag_len = strlen(flag);
    if (flag_len > sizeof(cb->flag_text) - 1)
        flag_len = sizeof(cb->flag_text) - 1;
    memcpy(cb->flag_text, flag, flag_len);
    if (flag_len < sizeof(cb->flag_text) - 1) {
        get_random(cb->flag_text + flag_len + 1, sizeof(cb->flag_text) - flag_len - 1);
    }
    cb->flag_key = 0;
    cb->cycle = 0;
    cb->jcycle = 0;
    // text section
    WD aslr = rand_integer() & 0xff;
    WD code_base = cb->pc = 0x200000 | (aslr << 12);
    //memcpy(cb->memory + (cb->pc >> 2), binary, sizeof(binary));
    memcpy(cb->memory + (code_base >> 2), rom_content, romsz);
}

// address mask
static const WD AMSK = (1 << 22) - 1;

// util function for handling subword reads / writes

static WD get_subword(WD word, WD addr, int n)
{
    addr = addr & 3 & (-n);
    return (word >> (8 * addr)) & ((1l << (8 * n)) - 1);
}

static WD write_subword(WD new_val, WD old_word, WD addr, int n)
{
    addr = addr & 3 & (-n);
    WD mask = ((1l << (8 * n)) - 1) << (8 * addr);
    return (old_word & ~mask) | ((new_val << (8 * addr)) & mask);
}

// read dma mem (<128bytes)

static WD read_dma(const struct control_block* cb, WD address, bool forced)
{
    WD code = (address >> 2);
    if (code >= 32) {
        return 0;
    }
    if (code >= 12) {
        return cb->flag[code - 12] ^ (cb->flag_key * (code * 2 + 1));
    }
    switch (address >> 2) {
    //case 0:
    //    return 0;
    case 1:
        return cb->pc;
    case 4:
        return cb->cycle;
    case 5:
        return forced && !(address & 3) ? sl_getchar() : 0;
    case 6:
        return sl_randint();
    case 7:
        return sl_gettime();
    case 8:
        return cb->jcycle;
    case 9:
        return cb->memstat;
    default:
        return 0;
    }
}

// write dma mem (<128bytes)

static void write_dma(struct control_block* cb, WD address, int n, WD value)
{
    WD code = (address >> 2);
    if (code >= 32) {
        return;
    }
    if (code >= 12) {
        WD orig = cb->flag[code - 12];
        WD read = orig ^ (cb->flag_key * (code * 2 + 1));
        WD v = write_subword(value, read, address, n) ^ orig;
        cb->flag_key = v * inv_list[code];
    } else if (address == 5 * 4) {
        sl_putchar(value & 0xff);
    } else if (address == 10 * 4) {
        sl_sleep(value);
    } else if (address == 11 * 4) {
        sl_halt(value);
    }
}

// read abs mem, input must be absolute

static WD read_abs(const struct control_block* cb, WD address, int n, bool forced)
{
    address &= AMSK;
    WD res = 0;
    if (address < 128) {
        res = read_dma(cb, address, forced);
    } else {
        WD off = (address >> 2) & ((1 << 20) - 1);
        res = cb->memory[off];
    }
    return get_subword(res, address, n);
}

// write abs mem, input must be absolute

static void write_abs(struct control_block* cb, WD address, int n, WD value)
{
    address &= AMSK;
    if (address < 128) {
        write_dma(cb, address, n, value);
    } else {
        // no TLB, we let OS to decide whether the page should be mapped
        WD off = (address >> 2) & ((1 << 20) - 1);
        cb->memory[off] = write_subword(value, cb->memory[off], address, n);
    }
}

// address translation, base+offset -> absolute address

static WD addr_translate(const struct control_block* cb, WD address)
{
    WD addr_type = (address >> 22) & ((1 << 6) - 1);
    WD base_addr = read_abs(cb, addr_type << 2, 4, false);
    return (base_addr + address) & AMSK;
}

// single step of vm

static void step(struct control_block* cb)
{
    WD pc = cb->pc;
    WD op_a = read_abs(cb, pc & AMSK, 4, false);
    WD op_b = read_abs(cb, (pc + 4) & AMSK, 4, false);
    WD o_op_c = read_abs(cb, (pc + 8) & AMSK, 4, false);
    WD new_pc = cb->pc = (pc + 12) & AMSK;
    int n = 0xf & (0x1244 >> ((o_op_c & 3) * 4));
    WD op_c = o_op_c & -4;
    WD ph_a = addr_translate(cb, op_a);
    WD ph_b = addr_translate(cb, op_b);
    WD ph_c = addr_translate(cb, op_c);
    WD A = read_abs(cb, ph_a, n, false);
    WD B = read_abs(cb, ph_b, n, true);
    write_abs(cb, ph_a, n, (A - B) & ((1l << (8 * n)) - 1));
    cb->cycle += 1;
    if (ph_c != new_pc && A < B) {
        cb->pc = ph_c;
        cb->jcycle += 1;
    }
    // on_step(cb, pc, op_a, op_b, op_c, n, ph_a, ph_b, ph_c, A, B, cb->pc);
}

static void run_forever(struct control_block* cb)
{
    int time_limit = 0x100000 + (rand_integer() & 0xfffff);
    for (int i = 0; i < time_limit; i++) {
        step(cb);
    }
    puts("Time Limit Exceeded");
    exit(-3);
}

static void do_emu(void)
{
    struct control_block cb = {};
    init_cb(&cb);
    run_forever(&cb);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage:\n\t%s rom.bin [flag]\n", argv[0]);
        return -1;
    }
    rom = argv[1];
    flag = argc > 2 ? argv[2] : NULL;
    init_env();
    do_emu();
    return 0;
}
