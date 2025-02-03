#include "sys.h"
#include "uacpi/internal/log.h"
#include "uacpi/status.h"
#include "uacpi/types.h"
#include "uacpi/uacpi.h"
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <stddef.h>
#include <stdint.h>

int ramfd;

static int main(void) {
    int error = syscall1(__NR_iopl, 3);
    if (error) {
        uacpi_log(UACPI_LOG_ERROR, "failed to set iopl: %d\n", error);
        return 1;
    }

    // `open("/dev/mem")` fails with ENOENT and `mknod("/dev/mem")` with EEXIST. Don't really care to figure it out.

    error = syscall2(__NR_mkdir, (uintptr_t)"/dev/afhaahga", S_IRWXU | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
    if (error) {
        uacpi_log(UACPI_LOG_ERROR, "failed to create dir: %d\n", error);
        return 1;
    }

    error = syscall3(__NR_mknod, (uintptr_t)"/dev/afhaahga/mem", S_IFCHR | S_IRUSR | S_IWUSR, 0x101);
    if (error) {
        uacpi_log(UACPI_LOG_ERROR, "failed to create mem: %d\n", error);
        return 1;
    }

    ramfd = syscall3(__NR_open, (uintptr_t)"/dev/afhaahga/mem", O_RDWR | O_SYNC, 0);
    if (ramfd < 0) {
        uacpi_log(UACPI_LOG_ERROR, "failed to open mem: %d\n", ramfd);
        return 1;
    }

    uacpi_status status = uacpi_initialize(0);
    if (uacpi_unlikely_error(status)) {
        uacpi_log(UACPI_LOG_ERROR, "uacpi init failed: %s\n", uacpi_status_to_string(status));
        return 1;
    }

    status = uacpi_namespace_load();
    if (uacpi_unlikely_error(status)) {
        uacpi_log(UACPI_LOG_ERROR, "uacpi namespace load failed: %s\n", uacpi_status_to_string(status));
        return 1;
    }

    return 0;
}

__attribute__((force_align_arg_pointer)) _Noreturn void _start(void) {
    syscall1(__NR_exit_group, main());
    __builtin_unreachable();
}
