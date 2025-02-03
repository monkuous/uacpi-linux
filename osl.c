#include "compiler.h"
#include "heap.h"
#include "main.h"
#include "sys.h"
#include "uacpi/internal/log.h"
#include "uacpi/kernel_api.h"
#include "uacpi/status.h"
#include "uacpi/types.h"
#include <linux/mman.h>
#include <linux/time.h>
#include <stdint.h>

#define STUB()                                                                                                         \
    do {                                                                                                               \
        uacpi_error("stub:%s\n", __func__);                                                                            \
        syscall1(__NR_exit_group, 1);                                                                                  \
        __builtin_unreachable();                                                                                       \
    } while (0)

void *uacpi_kernel_alloc(uacpi_size size) {
    return allocate(size);
}

void uacpi_kernel_free(void *mem, uacpi_size size_hint) {
    free(mem, size_hint);
}

uacpi_handle uacpi_kernel_create_mutex(void) {
    return allocate(0);
}

void uacpi_kernel_free_mutex(uacpi_handle handle) {
    free(handle, 0);
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle handle, uacpi_u16 timeout) {
    return UACPI_STATUS_OK;
}

void uacpi_kernel_release_mutex(uacpi_handle handle) {
}

uacpi_thread_id uacpi_kernel_get_thread_id(void) {
    return NULL;
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle) {
    return 0;
}

void uacpi_kernel_unlock_spinlock(uacpi_handle handle, uacpi_cpu_flags flags) {
}

void uacpi_kernel_signal_event(uacpi_handle handle) {
    STUB();
}

void uacpi_kernel_reset_event(uacpi_handle handle) {
    STUB();
}

uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle handle, uacpi_u16 timeout) {
    STUB();
}

uacpi_status uacpi_kernel_wait_for_work_completion(void) {
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_handle uacpi_kernel_create_spinlock(void) {
    return allocate(0);
}

void uacpi_kernel_free_spinlock(uacpi_handle handle) {
    free(handle, 0);
}

uacpi_status uacpi_kernel_install_interrupt_handler(
        uacpi_u32 irq,
        uacpi_interrupt_handler handler,
        uacpi_handle ctx,
        uacpi_handle *out_irq_handle
) {
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(uacpi_interrupt_handler handler, uacpi_handle irq_handle) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_handle uacpi_kernel_create_event(void) {
    STUB();
}

void uacpi_kernel_free_event(uacpi_handle handle) {
    STUB();
}

uacpi_status uacpi_kernel_schedule_work(uacpi_work_type type, uacpi_work_handler handler, uacpi_handle ctx) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size len, uacpi_handle *out_handle) {
    *out_handle = (void *)base;
    return UACPI_STATUS_OK;
}

void uacpi_kernel_io_unmap(uacpi_handle handle) {
}

uacpi_status uacpi_kernel_pci_device_open(uacpi_pci_address address, uacpi_handle *out_handle) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

void uacpi_kernel_pci_device_close(uacpi_handle handle) {
    STUB();
}

void uacpi_kernel_stall(uacpi_u8 usec) {
    STUB();
}

void uacpi_kernel_sleep(uacpi_u64 msec) {
    STUB();
}

uacpi_status uacpi_kernel_io_read8(uacpi_handle handle, uacpi_size offset, uacpi_u8 *out_value) {
    asm volatile("inb %1, %0" : "=a"(*out_value) : "Nd"((uint16_t)(uintptr_t)handle) : "memory");
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read16(uacpi_handle handle, uacpi_size offset, uacpi_u16 *out_value) {
    asm volatile("inw %1, %0" : "=a"(*out_value) : "Nd"((uint16_t)(uintptr_t)handle) : "memory");
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read32(uacpi_handle handle, uacpi_size offset, uacpi_u32 *out_value) {
    asm volatile("inl %1, %0" : "=a"(*out_value) : "Nd"((uint16_t)(uintptr_t)handle) : "memory");
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write8(uacpi_handle handle, uacpi_size offset, uacpi_u8 in_value) {
    asm("outb %0, %1" ::"a"(in_value), "Nd"((uint16_t)(uintptr_t)handle) : "memory");
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write16(uacpi_handle handle, uacpi_size offset, uacpi_u16 in_value) {
    asm("outw %0, %1" ::"a"(in_value), "Nd"((uint16_t)(uintptr_t)handle) : "memory");
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write32(uacpi_handle handle, uacpi_size offset, uacpi_u32 in_value) {
    asm("outl %0, %1" ::"a"(in_value), "Nd"((uint16_t)(uintptr_t)handle) : "memory");
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read8(uacpi_handle device, uacpi_size offset, uacpi_u8 *value) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_status uacpi_kernel_pci_read16(uacpi_handle device, uacpi_size offset, uacpi_u16 *value) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_status uacpi_kernel_pci_read32(uacpi_handle device, uacpi_size offset, uacpi_u32 *value) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_status uacpi_kernel_pci_write8(uacpi_handle device, uacpi_size offset, uacpi_u8 value) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_status uacpi_kernel_pci_write16(uacpi_handle device, uacpi_size offset, uacpi_u16 value) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_status uacpi_kernel_pci_write32(uacpi_handle device, uacpi_size offset, uacpi_u32 value) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len) {
    uacpi_phys_addr offset = addr & 0xfff;
    uacpi_phys_addr start = addr & ~0xfff;
    uacpi_phys_addr end = (addr + len + 0xfff) & ~0xfff;

    long ret = syscall6(__NR_mmap, 0, end - start, PROT_READ | PROT_WRITE, MAP_SHARED, ramfd, start);
    if (unlikely(ret < 0)) {
        uacpi_log(UACPI_LOG_ERROR, "phys mem map failed: %ld\n", ret);
        return NULL;
    }
    return (void *)(ret + offset);
}

void uacpi_kernel_unmap(void *addr, uacpi_size len) {
    uintptr_t start = (uintptr_t)addr & ~0xfff;
    uintptr_t end = ((uintptr_t)addr + len + 0xfff) & ~0xfff;
    syscall2(__NR_munmap, start, end - start);
}

static void printS(const void *data, size_t count) {
    syscall3(__NR_write, 2, (uintptr_t)data, count);
}

static void prints(const char *s) {
    size_t n = 0;
    while (s[n]) n += sizeof(*s);
    printS(s, n);
}

static void printd(int i) {
    unsigned char buffer[32];
    size_t index = sizeof(buffer);

    do {
        buffer[--index] = '0' + (i % 10);
        i /= 10;
    } while (i > 0);

    printS(&buffer[index], sizeof(buffer) - index);
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *str) {
    printS("uacpi[", 6);
    printd(level);
    printS("] ", 2);
    prints(str);
}

uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request *request) {
    return UACPI_STATUS_UNIMPLEMENTED;
    STUB();
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void) {
    struct timespec spec;
    syscall2(__NR_clock_gettime, CLOCK_MONOTONIC, (uintptr_t)&spec);
    return (spec.tv_sec * 1000000000ul) + spec.tv_nsec;
}

typedef struct {
    uint16_t value;
} __attribute__((aligned(1))) unaligned16_t;

static int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *b1 = s1;
    const unsigned char *b2 = s2;

    for (size_t i = 0; i < n; i++) {
        unsigned char c1 = b1[i];
        unsigned char c2 = b2[i];

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
    }

    return 0;
}

static bool search_area(uintptr_t start, size_t size, uacpi_phys_addr *out) {
    void *area = uacpi_kernel_map(start, size);

    for (size_t offset = 0; offset < size; offset += 16) {
        void *ptr = area + offset;

        if (memcmp(ptr, "RSD PTR ", 8) == 0) {
            *out = start + offset;
            uacpi_kernel_unmap(area, size);
            return true;
        }
    }

    uacpi_kernel_unmap(area, size);
    return false;
}

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address) {
    unaligned16_t *ptr = uacpi_kernel_map(0x40e, sizeof(*ptr));
    uintptr_t ebda = (uintptr_t)ptr->value * 16;
    uacpi_kernel_unmap(ptr, sizeof(*ptr));

    if (search_area(ebda, 1024, out_rsdp_address)) return UACPI_STATUS_OK;
    if (search_area(0xe0000, 0x20000, out_rsdp_address)) return UACPI_STATUS_OK;

    return UACPI_STATUS_NOT_FOUND;
}
