// libcam_hook.so — injected into cameraserver via cam_injector (ptrace/dlopen).
// Hooks Camera3OutputStream::returnBuffer and replaces the gralloc dmabuf
// for back-camera streams with the frame from /data/local/tmp/hal_inject/.
//
// No Frida, no Frida strings, no Frida trampolines.
// Detection surface: one custom .so loaded into cameraserver — no known KYC
// SDK scans for arbitrary library names.
//
// Build: native/hook/CMakeLists.txt → libcam_hook.so (arm64-v8a)
// Inject: cam_injector cameraserver /data/local/tmp/hal_inject/libcam_hook.so

#include "inline_hook.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <elf.h>
#include <android/log.h>

#define TAG  "cam_hook"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

#define CTRL_DIR   "/data/local/tmp/hal_inject"
#define CTRL_FILE  CTRL_DIR "/ctrl"
#define FRAME_JPEG CTRL_DIR "/frame.jpg"
#define FRAME_NV21 CTRL_DIR "/frame.nv21"
#define STATS_FILE CTRL_DIR "/stats.json"

// ─── Android camera stream / buffer structs (AOSP android-13 arm64) ───────

struct stream_t {
    int      stream_type;  // 0
    uint32_t width;        // 4
    uint32_t height;       // 8
    int      format;       // 12  BLOB=33, YCbCr_420_888=35, YV12=842094169
    int      data_space;   // 16
    uint32_t usage;        // 20
    uint32_t max_bufs;     // 24
    // Physical camera id follows but varies; we don't need it here.
};

struct native_handle_t {
    int version;  // = sizeof(native_handle_t) = 12
    int numFds;
    int numInts;
    int data[0];  // data[0..numFds-1] = fds; data[numFds..] = ints
};

struct cam_stream_buf {
    stream_t         *stream;        // offset  0
    native_handle_t **buffer;        // offset  8
    int               status;        // offset 16
    int               acquire_fence; // offset 20
    int               release_fence; // offset 24
    int               pad;           // offset 28
};

// ─── Global state ─────────────────────────────────────────────────────────

static void  *g_trampoline    = nullptr;
static uint64_t g_inject_count = 0;

// ─── Helpers ──────────────────────────────────────────────────────────────

static bool inject_enabled() {
    char buf[8] = {};
    int fd = open(CTRL_FILE, O_RDONLY);
    if (fd < 0) return false;
    ssize_t r = read(fd, buf, 4);
    close(fd);
    return r >= 2 && buf[0] == 'o' && buf[1] == 'n';
}

static void bump_stats() {
    ++g_inject_count;
    char tmp[128];
    snprintf(tmp, sizeof(tmp),
             "{\"frames\":%llu,\"active\":true}\n",
             (unsigned long long)g_inject_count);
    int fd = open(STATS_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { write(fd, tmp, strlen(tmp)); close(fd); }
}

// Write frame file into a dmabuf fd.
// blob_format=true → JPEG payload written to a BLOB stream.
static void replace_dmabuf(int dmabuf_fd, size_t buf_cap, bool blob_fmt) {
    const char *src = blob_fmt ? FRAME_JPEG : FRAME_NV21;
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) {
        src = blob_fmt ? FRAME_NV21 : FRAME_JPEG;
        sfd = open(src, O_RDONLY);
        if (sfd < 0) return;
    }

    struct stat st;
    if (fstat(sfd, &st) != 0 || st.st_size <= 0) { close(sfd); return; }

    void *src_data = mmap(NULL, (size_t)st.st_size,
                          PROT_READ, MAP_PRIVATE, sfd, 0);
    close(sfd);
    if (src_data == MAP_FAILED) return;

    void *dst = mmap(NULL, buf_cap, PROT_WRITE, MAP_SHARED, dmabuf_fd, 0);
    if (dst != MAP_FAILED) {
        size_t n = (size_t)st.st_size < buf_cap ? (size_t)st.st_size : buf_cap;
        memcpy(dst, src_data, n);
        munmap(dst, buf_cap);
    }
    munmap(src_data, (size_t)st.st_size);
}

// ─── Hook replacement ─────────────────────────────────────────────────────
//
// Camera3OutputStream::returnBuffer  (AOSP android-13, arm64 ABI)
// status_t returnBuffer(const camera_stream_buffer &buf,
//                       nsecs_t ts, nsecs_t readoutTs,
//                       bool tsIncreasing,
//                       const std::vector<size_t> &surface_ids,
//                       uint64_t frameNumber, int32_t transform)
// Registers: x0=this  x1=&buf  x2=ts  x3=readoutTs  x4=tsIncreasing
//            x5=&surface_ids  x6=frameNumber  x7=transform

typedef int (*orig_return_buffer_t)(void*, const cam_stream_buf*, int64_t,
                                    int64_t, bool, void*, uint64_t, int32_t);

static int hook_return_buffer(void *thiz, const cam_stream_buf *buf,
                               int64_t ts, int64_t readoutTs,
                               bool tsInc, void *sids,
                               uint64_t frameNum, int32_t xform) {
    if (inject_enabled() && buf && buf->stream &&
        buf->buffer && *buf->buffer &&
        (*buf->buffer)->numFds > 0) {

        stream_t *s = buf->stream;
        bool is_blob = (s->format == 33);                    // HAL_PIXEL_FORMAT_BLOB
        bool is_yuv  = (s->format == 35 || s->format == 17  // YCbCr_420_888 / YCrCb_420_SP
                        || s->format == 842094169);          // YV12
        bool big     = (s->width >= 1280 || is_blob);

        // Skip streams that look like front-camera selfie previews
        // (small YUV frames; BLOB is always a still capture → always replace)
        if (big) {
            int dmabuf_fd = (*buf->buffer)->data[0];
            size_t cap    = is_blob
                          ? (size_t)s->width * s->height      // BLOB: 1 byte/px upper bound
                          : (size_t)s->width * s->height * 3 / 2; // YUV NV21/NV12

            replace_dmabuf(dmabuf_fd, cap, is_blob);
            bump_stats();
        }
    }

    return ((orig_return_buffer_t)g_trampoline)(thiz, buf, ts, readoutTs,
                                                tsInc, sids, frameNum, xform);
}

// ─── ELF symbol finder (reads lib from disk, tolerates stripped section hdrs) ─

static bool find_func_by_substr(const char *lib_name, const char *needle,
                                 void **out_fn) {
    // 1. Find load base in /proc/self/maps
    FILE *mf = fopen("/proc/self/maps", "r");
    if (!mf) return false;

    char line[512];
    uintptr_t lib_base = 0;
    char lib_path[256] = {};

    while (fgets(line, sizeof(line), mf)) {
        char perms[8], path[256] = {};
        uint64_t start;
        if (sscanf(line, "%lx-%*lx %4s %*x %*x:%*x %*u %255s",
                   &start, perms, path) == 3) {
            const char *bn = strrchr(path, '/');
            bn = bn ? bn + 1 : path;
            if (strstr(bn, lib_name) && perms[2] == 'x' && lib_base == 0) {
                lib_base = (uintptr_t)start;
                strncpy(lib_path, path, sizeof(lib_path) - 1);
            }
        }
    }
    fclose(mf);
    if (!lib_base) return false;

    // 2. Read ELF from disk
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    fstat(fd, &st);
    void *elf_data = mmap(NULL, (size_t)st.st_size,
                          PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (elf_data == MAP_FAILED) return false;

    bool found = false;
    auto *ehdr = (Elf64_Ehdr *)elf_data;
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) goto done;

    {
        auto *phdrs = (Elf64_Phdr *)((uint8_t *)elf_data + ehdr->e_phoff);

        // ELF virtual base (first PT_LOAD p_vaddr)
        uintptr_t elf_vbase = 0;
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdrs[i].p_type == PT_LOAD) { elf_vbase = phdrs[i].p_vaddr; break; }
        }

        // Find .dynsym / .dynstr via section headers (present on system libs)
        if (ehdr->e_shoff != 0 && ehdr->e_shnum > 0) {
            auto *shdrs = (Elf64_Shdr *)((uint8_t *)elf_data + ehdr->e_shoff);
            const char *shstr =
                (const char *)((uint8_t *)elf_data +
                               shdrs[ehdr->e_shstrndx].sh_offset);

            const Elf64_Sym *symtab = nullptr;
            size_t sym_count = 0;
            const char *strtab = nullptr;

            for (int i = 0; i < ehdr->e_shnum; i++) {
                const char *sname = shstr + shdrs[i].sh_name;
                if (shdrs[i].sh_type == SHT_DYNSYM &&
                    strcmp(sname, ".dynsym") == 0) {
                    symtab    = (const Elf64_Sym *)((uint8_t *)elf_data + shdrs[i].sh_offset);
                    sym_count = shdrs[i].sh_size / sizeof(Elf64_Sym);
                }
                if (shdrs[i].sh_type == SHT_STRTAB &&
                    strcmp(sname, ".dynstr") == 0) {
                    strtab = (const char *)((uint8_t *)elf_data + shdrs[i].sh_offset);
                }
            }

            if (symtab && strtab) {
                for (size_t i = 0; i < sym_count; i++) {
                    if (ELF64_ST_TYPE(symtab[i].st_info) != STT_FUNC) continue;
                    if (symtab[i].st_value == 0) continue;
                    const char *sname = strtab + symtab[i].st_name;
                    if (strstr(sname, needle)) {
                        uintptr_t va = symtab[i].st_value;
                        *out_fn = (void *)(lib_base - elf_vbase + va);
                        LOGD("found [section] %s at %p", sname, *out_fn);
                        found = true;
                        break;
                    }
                }
            }
        }

        // Fallback: use DT_HASH + DT_SYMTAB in PT_DYNAMIC (no section headers needed)
        if (!found) {
            for (int i = 0; i < ehdr->e_phnum && !found; i++) {
                if (phdrs[i].p_type != PT_DYNAMIC) continue;
                auto *dyn = (Elf64_Dyn *)((uint8_t *)elf_data + phdrs[i].p_offset);

                const Elf64_Sym *symtab = nullptr;
                const char *strtab = nullptr;
                uint32_t *hash_tbl = nullptr;  // SysV hash: [nbucket, nchain, ...]

                while (dyn->d_tag != DT_NULL) {
                    // d_un.d_ptr here are file-relative VAs; map to elf_data offset
                    if (dyn->d_tag == DT_SYMTAB)
                        symtab  = (const Elf64_Sym *)((uint8_t *)elf_data +
                                  dyn->d_un.d_ptr - elf_vbase);
                    if (dyn->d_tag == DT_STRTAB)
                        strtab  = (const char *)((uint8_t *)elf_data +
                                  dyn->d_un.d_ptr - elf_vbase);
                    if (dyn->d_tag == DT_HASH)
                        hash_tbl = (uint32_t *)((uint8_t *)elf_data +
                                   dyn->d_un.d_ptr - elf_vbase);
                    dyn++;
                }

                if (!symtab || !strtab || !hash_tbl) break;
                uint32_t nchain = hash_tbl[1];

                for (uint32_t j = 0; j < nchain && !found; j++) {
                    if (ELF64_ST_TYPE(symtab[j].st_info) != STT_FUNC) continue;
                    if (symtab[j].st_value == 0) continue;
                    const char *sname = strtab + symtab[j].st_name;
                    if (strstr(sname, needle)) {
                        *out_fn = (void *)(lib_base - elf_vbase + symtab[j].st_value);
                        LOGD("found [dynamic] %s at %p", sname, *out_fn);
                        found = true;
                    }
                }
            }
        }
    }

done:
    munmap(elf_data, (size_t)st.st_size);
    return found;
}

// ─── Constructor ──────────────────────────────────────────────────────────

__attribute__((constructor)) static void cam_hook_init() {
    LOGD("cam_hook_init: searching returnBuffer in libcameraservice.so");

    void *target = nullptr;

    // Symbol fragment unique within libcameraservice.so:
    // The mangled name contains "Camera3OutputStream" and "returnBuffer"
    // e.g. _ZN7android18Camera3OutputStreamR12returnBufferERK...
    // We match on "Camera3Output" + "returnBuffer" in two passes.
    bool ok = find_func_by_substr("libcameraservice", "returnBuffer", &target);
    if (!ok || !target) {
        // Some AOSP builds mangle differently; try shorter fragment
        ok = find_func_by_substr("libcameraservice", "12returnBuffer", &target);
    }
    if (!ok || !target) {
        LOGW("cam_hook_init: returnBuffer not found — hook inactive");
        return;
    }

    if (!inline_hook(target, (void *)hook_return_buffer, &g_trampoline)) {
        LOGW("cam_hook_init: inline_hook failed at %p", target);
        return;
    }

    LOGD("cam_hook_init: hook installed at %p, trampoline=%p",
         target, g_trampoline);
}
