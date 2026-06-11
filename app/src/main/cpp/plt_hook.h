#ifndef PLT_HOOK_H
#define PLT_HOOK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// PLT hook: replace function in GOT of all loaded libraries
int plt_hook_register(const char *symbol, void *new_func, void **old_func);

// Apply all registered hooks
int plt_hook_commit();

#ifdef __cplusplus
}
#endif

#endif // PLT_HOOK_H
