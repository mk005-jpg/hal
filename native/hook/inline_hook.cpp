#include "inline_hook.h"
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// arm64 absolute-jump trampoline (16 bytes):
//   LDR X16, [PC, #8]   ; 0x58000050
//   BR  X16             ; 0xD61F0200
//   .qword <destination>

static const uint32_t TRAMP_LDR  = 0x58000050u; // LDR X16, [PC+8]
static const uint32_t TRAMP_BR   = 0xD61F0200u; // BR X16

static const size_t HOOK_BYTES  = 16;
static const size_t TRAMP_SIZE  = 32; // 16 (saved prologue) + 4+4+8 (jump-back)

static uintptr_t page_floor(uintptr_t a) {
    return a & ~((uintptr_t)(getpagesize() - 1));
}

bool inline_hook(void *target, void *replacement, void **trampoline_out) {
    if (!target || !replacement || !trampoline_out) return false;

    // Allocate rwx call-through trampoline
    void *tramp = mmap(NULL, TRAMP_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return false;

    // [0..15]  = saved first 16 bytes of original function
    memcpy(tramp, target, HOOK_BYTES);

    // [16..31] = LDR X16, +8; BR X16; .qword original+16
    uint32_t *jb = (uint32_t *)((uint8_t *)tramp + HOOK_BYTES);
    jb[0] = TRAMP_LDR;
    jb[1] = TRAMP_BR;
    uint64_t cont = (uint64_t)((uint8_t *)target + HOOK_BYTES);
    memcpy(&jb[2], &cont, sizeof(cont));
    __builtin___clear_cache((char *)tramp, (char *)((uint8_t *)tramp + TRAMP_SIZE));

    // Make target writable (two pages to handle split-page case)
    uintptr_t page = page_floor((uintptr_t)target);
    int ps = getpagesize();
    if (mprotect((void *)page, (size_t)ps * 2,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        munmap(tramp, TRAMP_SIZE);
        return false;
    }

    // Write absolute jump to replacement at target
    uint32_t *h = (uint32_t *)target;
    h[0] = TRAMP_LDR;
    h[1] = TRAMP_BR;
    uint64_t rep = (uint64_t)replacement;
    memcpy(&h[2], &rep, sizeof(rep));
    __builtin___clear_cache((char *)target, (char *)((uint8_t *)target + HOOK_BYTES));

    mprotect((void *)page, (size_t)ps * 2, PROT_READ | PROT_EXEC);

    *trampoline_out = tramp;
    return true;
}

void inline_hook_free(void *trampoline) {
    if (trampoline) munmap(trampoline, TRAMP_SIZE);
}
