
// Implementation for stack-protector callback, mostly taken from
// article at https://wiki.osdev.org/Stack_Smashing_Protector
//
// How to use:
//  Add "-fstack-protector" or "-fstack-protector-all" to GCC command
//
#ifndef __linux__

#if defined(TOOLCHAIN_GCC_ARM)

#include "mbed_interface.h" // mbed_die
#include "mbed_error.h" // error()

#include <stdint.h>
 
// Use a non-RAM odd address as canary, which should cause hard fault if used as pointer.
#if UINT32_MAX == UINTPTR_MAX
#define STACK_CHK_GUARD 0xe2dee395
#else
#define STACK_CHK_GUARD 0x595e9fbd94fda766
#endif

uintptr_t __stack_chk_guard = STACK_CHK_GUARD;

__attribute__((noreturn))
void __stack_chk_fail(void)
{
    // Log something before dying with a hint who did the stack overflow.
    error("** stack smashing detected at 0x%x ***", (unsigned int) MBED_CALLER_ADDR());

    mbed_die();

    while (1) {
        // loop forever, here to just in case the mbed_die is overridden to be non-fatal
    }
}

#endif

#endif
