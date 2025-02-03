#include "heap.h"
#include "compiler.h"
#include "sys.h"
#include <linux/mman.h>
#include <stddef.h>
#include <stdint.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))

#define MIN_ORDER 4
#define MAX_ORDER 15
#define MIN_SIZE (1ul << MIN_ORDER)

#define LARGE_SIZE (1ul << (MAX_ORDER + 1))
#define LARGE_MASK (LARGE_SIZE - 1)

struct free_obj {
    struct free_obj *next;
};

static struct free_obj *objects[MAX_ORDER - MIN_ORDER + 1];

static int size_to_order(size_t size) {
    return 64 - __builtin_clzl(size - 1);
}

void *allocate(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;
    if (likely(size < MIN_SIZE)) size = MIN_SIZE;

    int order = size_to_order(size);

    if (likely(order <= MAX_ORDER)) {
        struct free_obj *obj = objects[order - MIN_ORDER];
        if (likely(obj)) {
            objects[order - MIN_ORDER] = obj->next;
            return obj;
        }

        long ret = syscall6(__NR_mmap, 0, LARGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (unlikely(ret < 0)) return NULL;
        obj = (void *)ret;

        struct free_obj *objs = obj;
        struct free_obj *last = obj;

        for (size_t i = 1ul << order; i < LARGE_SIZE; i += 1ul << order) {
            struct free_obj *cur = (void *)obj + i;
            last->next = cur;
            last = cur;
        }

        last->next = objects[order - MIN_ORDER];
        objects[order - MIN_ORDER] = objs->next;

        return obj;
    }

    size = (size + LARGE_MASK) & ~LARGE_MASK;

    long ret = syscall6(__NR_mmap, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (unlikely(ret < 0)) return NULL;
    return (void *)ret;
}

void free(void *ptr, size_t size) {
    if (unlikely(size == 0)) return;
    if (likely(size < MIN_SIZE)) size = MIN_SIZE;

    int order = size_to_order(size);

    if (likely(order <= MAX_ORDER)) {
        struct free_obj *obj = ptr;
        obj->next = objects[order - MIN_ORDER];
        objects[order - MIN_ORDER] = obj;
        return;
    }

    syscall2(__NR_munmap, (uintptr_t)ptr, size);
}
