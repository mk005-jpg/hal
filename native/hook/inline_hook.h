#pragma once
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// arm64 inline hook — overwrites 16 bytes at target with a trampoline that
// branches to replacement.  Allocates rwx memory for call-through (*trampoline_out):
// call *trampoline_out to invoke the original function with the same arguments.
//
// Requirements:
//   • target must be in a mapped executable page (mprotect rw+x applied internally)
//   • first 16 bytes of target must not contain PC-relative branches beyond ±512 MB
//     (stack-setup prologues are always safe; PLT stubs: safe)
//   • caller must flush icache if target page is shared across CPUs
//
// Returns true on success; *trampoline_out is valid until inline_hook_free().
bool inline_hook(void *target, void *replacement, void **trampoline_out);

// Free the trampoline returned by inline_hook.  Passing NULL is a no-op.
void inline_hook_free(void *trampoline);

#ifdef __cplusplus
}
#endif
