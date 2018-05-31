/* mbed Microcontroller Library
 * Copyright (c) 2006-2013 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "platform/mbed_assert.h"
#include "device.h"

#include "platform/mbed_interface.h"
#include "platform/mbed_critical.h"

#if defined(TOOLCHAIN_GCC)

#include <unwind.h>

static int backtrace_index;

// Note: this may need "-funwind-tables" option given to GCC

// callback for the backtrace unwinder, will be called once for each level
static _Unwind_Reason_Code dump_backtrace_callback(struct _Unwind_Context *context, void *arg)
{
    void *ip = (void *)_Unwind_GetIP(context);

    // frame address, can be decoded with:
    // "addr2line <address> -e <your-binary.elf>"
    mbed_error_printf("#%d func address: %p\n", backtrace_index++, ip);

    return _URC_NO_REASON;
}

// this will at least give the callstack call addresses, which can be demangled offline
static dump_backtrace(void)
{
    mbed_error_printf("backtrace start:\n");

    backtrace_index = 0;

    _Unwind_Backtrace((_Unwind_Trace_Fn)&dump_backtrace_callback, 0);

    // log something at the end to make it visible if the backtrace code died.
    mbed_error_printf("backtrace done\n");
}
#else
static dump_backtrace(void)
{
    // todo: implement, if possible
}
#endif

void mbed_assert_internal(const char *expr, const char *file, int line)
{
    core_util_critical_section_enter();
    mbed_error_printf("mbed assertation failed: %s, file: %s, line %d\n", expr, file, line);

    // experimental backtrace, works on my machine with GCC and debug profile with -funwind-tables"
    dump_backtrace();

    mbed_die();
}
