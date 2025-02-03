# uacpi-linux
[uACPI](https://github.com/uACPI/uACPI) running on Linux in userspace.

> [!WARNING]
> DO NOT RUN THIS ON YOUR HOST SYSTEM. uACPI interfaces with hardware directly,
> and therefore this application interferes with Linux's builtin ACPI drivers.
> To avoid this, you must use a kernel compiled with `CONFIG_ACPI=0`. Even if
> you do, it is not recommended to run this outside of a virtual machine.

There is no real use case for this. It only exists because the author was
curious about its performance. It is mostly nonfunctional, because it is
impossible to handle interrupts in userspace on Linux unless you write a small
accompanying kernel module. It will not be maintained.
