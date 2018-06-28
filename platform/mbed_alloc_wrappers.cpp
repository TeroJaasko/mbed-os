/* mbed Microcontroller Library
 * Copyright (c) 2006-2016 ARM Limited
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

#include "platform/mbed_mem_trace.h"
#include "platform/mbed_stats.h"
#include "platform/mbed_toolchain.h"
#include "platform/SingletonPtr.h"
#include "platform/PlatformMutex.h"
#include "mbed_assert.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* There are two memory tracers in mbed OS:

- the first can be used to detect the maximum heap usage at runtime. It is
  activated by defining the MBED_HEAP_STATS_ENABLED macro.
- the second can be used to trace each memory call by automatically invoking
  a callback on each memory operation (see hal/api/mbed_mem_trace.h). It is
  activated by defining the MBED_MEM_TRACING_ENABLED macro.

Both tracers can be activated and deactivated in any combination. If both tracers
are active, the second one (MBED_MEM_TRACING_ENABLED) will trace the first one's
(MBED_HEAP_STATS_ENABLED) memory calls.*/

/******************************************************************************/
/* Implementation of the runtime max heap usage checker                       */
/******************************************************************************/

#ifdef MBED_HEAP_STATS_ENABLED
#if defined(TOOLCHAIN_GCC)
#include "ns_list.h"
//XXX #define HEAP_INTEGRITY_CHECK 1
#endif
#endif

/* Size must be a multiple of 8 to keep alignment */
typedef struct {
    uint32_t size;
#ifdef HEAP_INTEGRITY_CHECK
    // this is 8 bytes, alignment guaranteed
    ns_list_link_t link;
#endif
    uint32_t pad;
} alloc_info_t;

#ifdef MBED_HEAP_STATS_ENABLED
static SingletonPtr<PlatformMutex> malloc_stats_mutex;
static mbed_stats_heap_t heap_stats = {0, 0, 0, 0, 0};

#ifdef HEAP_INTEGRITY_CHECK
static NS_LIST_DEFINE(heap_alloc_info_list, alloc_info_t, link);
// This counts the amount of allocations/frees after which the heap scan is done.
// The scan is taking some time, and if done on each operation, it breaks the mbedtls
// handshake as it does tens of thousands of allocation+free pairs.
static int alloc_check;
#endif

#endif

void mbed_stats_heap_get(mbed_stats_heap_t *stats)
{
#ifdef MBED_HEAP_STATS_ENABLED
    extern uint32_t mbed_heap_size;
    heap_stats.reserved_size = mbed_heap_size;

    malloc_stats_mutex->lock();
    memcpy(stats, &heap_stats, sizeof(mbed_stats_heap_t));
    malloc_stats_mutex->unlock();
#else
    memset(stats, 0, sizeof(mbed_stats_heap_t));
#endif
}

/******************************************************************************/
/* GCC memory allocation wrappers                                             */
/******************************************************************************/

#if defined(TOOLCHAIN_GCC)

#ifdef   FEATURE_UVISOR
#include "uvisor-lib/uvisor-lib.h"
#endif/* FEATURE_UVISOR */

extern "C" {
    void * __real__malloc_r(struct _reent * r, size_t size);
    void * __real__memalign_r(struct _reent * r, size_t alignment, size_t bytes);
    void * __real__realloc_r(struct _reent * r, void * ptr, size_t size);
    void __real__free_r(struct _reent * r, void * ptr);
    void* __real__calloc_r(struct _reent * r, size_t nmemb, size_t size);
    void* malloc_wrapper(struct _reent * r, size_t size, void * caller);
    void free_wrapper(struct _reent * r, void * ptr, void* caller);
}

// TODO: memory tracing doesn't work with uVisor enabled.
#if !defined(FEATURE_UVISOR)

extern "C" void * __wrap__malloc_r(struct _reent * r, size_t size) {
    return malloc_wrapper(r, size, MBED_CALLER_ADDR());
}

#define ALLOC_POSTFIX_CANARY_LENGTH 8


#if HEAP_INTEGRITY_CHECK
// Scan trough the list of allocated cells and verify their canaries. Will have O(N) performance
// impact, so use with care. This is needed as the per-cell checks are done at malloc() and free().
// It is also possible, that allocated cell may not have been freed at all while its content has
// overwritten next cell header and which then causes a fault later at the real_malloc() or real_free().
static void validate_heap() {

    alloc_check--;

    if (alloc_check > 0) {
        return;
    }

    // rate limit to every other operation
    alloc_check = 2;

    ns_list_foreach(const alloc_info_t, cell, &heap_alloc_info_list) {

        // each cell in list must have the magic value which marks it allocated
        MBED_ASSERT(cell->pad == 0xcafebabe);

        // verify that the data canary is intact
        const uint8_t* ptr = (uint8_t*)cell + sizeof(alloc_info_t);
        const uint8_t *canary = ptr + cell->size;

        for (int index = 0; index < ALLOC_POSTFIX_CANARY_LENGTH; index++) {
            MBED_ASSERT(canary[index] == 0xF3);
        }
    }
}
#endif


extern "C" void * malloc_wrapper(struct _reent * r, size_t size, void * caller) {
    void *ptr = NULL;
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif

    MBED_ASSERT(!IsIrqMode());

#ifdef MBED_HEAP_STATS_ENABLED
    malloc_stats_mutex->lock();

#if HEAP_INTEGRITY_CHECK
    // This scans trough the list of allocated cells and verifies their canaries. Will have O(N) performance
    validate_heap();
#endif

    alloc_info_t *alloc_info = (alloc_info_t*)__real__malloc_r(r, size + sizeof(alloc_info_t) + ALLOC_POSTFIX_CANARY_LENGTH);
    if (alloc_info != NULL) {
        alloc_info->size = size;
        alloc_info->pad = 0xcafebabe;
        ptr = (void*)(alloc_info + 1);
        heap_stats.current_size += size;
        heap_stats.total_size += size;
        heap_stats.alloc_cnt += 1;
        if (heap_stats.current_size > heap_stats.max_size) {
            heap_stats.max_size = heap_stats.current_size;
        }

#if HEAP_INTEGRITY_CHECK
        ns_list_add_to_end(&heap_alloc_info_list, alloc_info);
#endif

        // fill the freed mem up, forces values to be initialized with code, not by luck
        memset(ptr, 0xA5, size);

        // put a canary value after allocated memory so we can check on free if the buffer was overrun
        memset((uint8_t*)ptr + size, 0xF3, ALLOC_POSTFIX_CANARY_LENGTH);
    } else {
        heap_stats.alloc_fail_cnt += 1;
    }
    malloc_stats_mutex->unlock();
#else // #ifdef MBED_HEAP_STATS_ENABLED
    ptr = __real__malloc_r(r, size);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_malloc(ptr, size, caller);
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
    return ptr;
}

extern "C" void * __wrap__realloc_r(struct _reent * r, void * ptr, size_t size) {
    void *new_ptr = NULL;
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif
#ifdef MBED_HEAP_STATS_ENABLED
    // Implement realloc_r with malloc and free.
    // The function realloc_r can't be used here directly since
    // it can call into __wrap__malloc_r (returns ptr + 4) or
    // resize memory directly (returns ptr + 0).

    // Note - no lock needed since malloc and free are thread safe

    MBED_ASSERT(!IsIrqMode());

    // Get old size
    uint32_t old_size = 0;
    if (ptr != NULL) {
        alloc_info_t *alloc_info = ((alloc_info_t*)ptr) - 1;
        MBED_ASSERT(alloc_info->pad == 0xcafebabe);
        old_size = alloc_info->size;
    }

    // Allocate space
    if (size != 0) {
        new_ptr = malloc(size);
    }

    // If the new buffer has been allocated copy the data to it
    // and free the old buffer
    if (new_ptr != NULL) {

        // the postfix canary is checked by free(), no need to do it here
        uint32_t copy_size = (old_size < size) ? old_size : size;
        memcpy(new_ptr, (void*)ptr, copy_size);
        free(ptr);
    }
#else // #ifdef MBED_HEAP_STATS_ENABLED
    new_ptr = __real__realloc_r(r, ptr, size);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_realloc(new_ptr, ptr, size, MBED_CALLER_ADDR());
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
    return new_ptr;
}

extern "C" void __wrap__free_r(struct _reent * r, void * ptr) {
    free_wrapper(r, ptr, MBED_CALLER_ADDR());
}

extern "C" void free_wrapper(struct _reent * r, void * ptr, void * caller) {
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif

    // XXX: K64F hardcoding, to be taken from the linker generated values (__sram_end, etc)
#define RAM_START ((void*)0x20000000)
#define RAM_END ((void*)((uint8_t*)RAM_START + 0x30000))

    MBED_ASSERT(!IsIrqMode());
    MBED_ASSERT((ptr == 0) || ((RAM_START <= ptr) && (ptr <= RAM_END)));

#ifdef MBED_HEAP_STATS_ENABLED
    malloc_stats_mutex->lock();
    alloc_info_t *alloc_info = NULL;
    if (ptr != NULL) {

#if HEAP_INTEGRITY_CHECK
        validate_heap();
#endif
        alloc_info = ((alloc_info_t*)ptr) - 1;

        MBED_ASSERT(alloc_info->pad == 0xcafebabe);
        heap_stats.current_size -= alloc_info->size;
        heap_stats.alloc_cnt -= 1;
        alloc_info->pad = 0xdeadbeef;

#if HEAP_INTEGRITY_CHECK
        ns_list_remove(&heap_alloc_info_list, alloc_info);
#endif

        uint8_t *canary = (uint8_t *)ptr + alloc_info->size;
        for (int index = 0; index < ALLOC_POSTFIX_CANARY_LENGTH; index++) {

            MBED_ASSERT(canary[index] == 0xF3);
        }

        // fill the freed mem, so the content is invalid and use after free is more visible
        memset(ptr, 0xBB, alloc_info->size);

        // overwrite the canary too. Q: why not just leave it there?
        memset(canary, 0xF5, ALLOC_POSTFIX_CANARY_LENGTH);
    }
    __real__free_r(r, (void*)alloc_info);
    malloc_stats_mutex->unlock();
#else // #ifdef MBED_HEAP_STATS_ENABLED
    __real__free_r(r, ptr);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_free(ptr, caller);
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
}

extern "C" void * __wrap__calloc_r(struct _reent * r, size_t nmemb, size_t size) {
    void *ptr = NULL;
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif
#ifdef MBED_HEAP_STATS_ENABLED
    // Note - no lock needed since malloc is thread safe

    ptr = malloc(nmemb * size);
    if (ptr != NULL) {
        memset(ptr, 0, nmemb * size);
    }
#else // #ifdef MBED_HEAP_STATS_ENABLED
    ptr = __real__calloc_r(r, nmemb, size);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_calloc(ptr, nmemb, size, MBED_CALLER_ADDR());
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
    return ptr;
}

extern "C" void * __wrap__memalign_r(struct _reent * r, size_t alignment, size_t bytes) {
    return __real__memalign_r(r, alignment, bytes);
}

#endif // if !defined(FEATURE_UVISOR)


/******************************************************************************/
/* ARMCC / IAR memory allocation wrappers                                     */
/******************************************************************************/

#elif defined(TOOLCHAIN_ARM) || defined(__ICCARM__)

#if defined(TOOLCHAIN_ARM)
#define SUPER_MALLOC    $Super$$malloc
#define SUB_MALLOC      $Sub$$malloc
#define SUPER_REALLOC   $Super$$realloc
#define SUB_REALLOC     $Sub$$realloc
#define SUPER_CALLOC    $Super$$calloc
#define SUB_CALLOC      $Sub$$calloc
#define SUPER_FREE      $Super$$free
#define SUB_FREE        $Sub$$free
#elif defined(__ICCARM__)
#define SUPER_MALLOC    $Super$$__iar_dlmalloc
#define SUB_MALLOC      $Sub$$__iar_dlmalloc
#define SUPER_REALLOC   $Super$$__iar_dlrealloc
#define SUB_REALLOC     $Sub$$__iar_dlrealloc
#define SUPER_CALLOC    $Super$$__iar_dlcalloc
#define SUB_CALLOC      $Sub$$__iar_dlcalloc
#define SUPER_FREE      $Super$$__iar_dlfree
#define SUB_FREE        $Sub$$__iar_dlfree
#endif

/* Enable hooking of memory function only if tracing is also enabled */
#if defined(MBED_MEM_TRACING_ENABLED) || defined(MBED_HEAP_STATS_ENABLED)

extern "C" {
    void *SUPER_MALLOC(size_t size);
    void *SUPER_REALLOC(void *ptr, size_t size);
    void *SUPER_CALLOC(size_t nmemb, size_t size);
    void SUPER_FREE(void *ptr);
    void *malloc_wrapper(size_t size, void* caller);
    void free_wrapper(void *ptr, void* caller);
}


extern "C" void* SUB_MALLOC(size_t size) {
    return malloc_wrapper(size, MBED_CALLER_ADDR());
}

extern "C" void* malloc_wrapper(size_t size, void* caller) {
    void *ptr = NULL;
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif
#ifdef MBED_HEAP_STATS_ENABLED
    malloc_stats_mutex->lock();
    alloc_info_t *alloc_info = (alloc_info_t*)SUPER_MALLOC(size + sizeof(alloc_info_t));
    if (alloc_info != NULL) {
        alloc_info->size = size;
        ptr = (void*)(alloc_info + 1);
        heap_stats.current_size += size;
        heap_stats.total_size += size;
        heap_stats.alloc_cnt += 1;
        if (heap_stats.current_size > heap_stats.max_size) {
            heap_stats.max_size = heap_stats.current_size;
        }
    } else {
        heap_stats.alloc_fail_cnt += 1;
    }
    malloc_stats_mutex->unlock();
#else // #ifdef MBED_HEAP_STATS_ENABLED
    ptr = SUPER_MALLOC(size);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_malloc(ptr, size, caller);
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
    return ptr;
}


extern "C" void* SUB_REALLOC(void *ptr, size_t size) {
    void *new_ptr = NULL;
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif
#ifdef MBED_HEAP_STATS_ENABLED
    // Note - no lock needed since malloc and free are thread safe

    // Get old size
    uint32_t old_size = 0;
    if (ptr != NULL) {
        alloc_info_t *alloc_info = ((alloc_info_t*)ptr) - 1;
        old_size = alloc_info->size;
    }

    // Allocate space
    if (size != 0) {
        new_ptr = malloc(size);
    }

    // If the new buffer has been allocated copy the data to it
    // and free the old buffer
    if (new_ptr != NULL) {
        uint32_t copy_size = (old_size < size) ? old_size : size;
        memcpy(new_ptr, (void*)ptr, copy_size);
        free(ptr);
    }
#else // #ifdef MBED_HEAP_STATS_ENABLED
    new_ptr = SUPER_REALLOC(ptr, size);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_realloc(new_ptr, ptr, size, MBED_CALLER_ADDR());
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
    return new_ptr;
}

extern "C" void *SUB_CALLOC(size_t nmemb, size_t size) {
    void *ptr = NULL;
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif
#ifdef MBED_HEAP_STATS_ENABLED
    // Note - no lock needed since malloc is thread safe
    ptr = malloc(nmemb * size);
    if (ptr != NULL) {
        memset(ptr, 0, nmemb * size);
    }
#else // #ifdef MBED_HEAP_STATS_ENABLED
    ptr = SUPER_CALLOC(nmemb, size);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_calloc(ptr, nmemb, size, MBED_CALLER_ADDR());
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
    return ptr;
}

extern "C" void SUB_FREE(void *ptr) {
    free_wrapper(ptr, MBED_CALLER_ADDR());
}

extern "C" void free_wrapper(void *ptr, void* caller) {
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_lock();
#endif
#ifdef MBED_HEAP_STATS_ENABLED
    malloc_stats_mutex->lock();
    alloc_info_t *alloc_info = NULL;
    if (ptr != NULL) {
        alloc_info = ((alloc_info_t*)ptr) - 1;
        heap_stats.current_size -= alloc_info->size;
        heap_stats.alloc_cnt -= 1;
    }
    SUPER_FREE((void*)alloc_info);
    malloc_stats_mutex->unlock();
#else // #ifdef MBED_HEAP_STATS_ENABLED
    SUPER_FREE(ptr);
#endif // #ifdef MBED_HEAP_STATS_ENABLED
#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_free(ptr, caller);
    mbed_mem_trace_unlock();
#endif // #ifdef MBED_MEM_TRACING_ENABLED
}

#endif // #if defined(MBED_MEM_TRACING_ENABLED) || defined(MBED_HEAP_STATS_ENABLED)

/******************************************************************************/
/* Allocation wrappers for other toolchains are not supported yet             */
/******************************************************************************/

#else

#ifdef MBED_MEM_TRACING_ENABLED
#error Memory tracing is not supported with the current toolchain.
#endif

#ifdef MBED_HEAP_STATS_ENABLED
#error Heap statistics are not supported with the current toolchain.
#endif

#endif // #if defined(TOOLCHAIN_GCC)
