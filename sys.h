#pragma once

#include <asm/unistd.h>
#include <stddef.h>

static inline long syscall1(size_t num, size_t a0) {
    long value;
    asm volatile("syscall" : "=a"(value) : "a"(num), "D"(a0) : "memory", "rcx", "r11");
    return value;
}

static inline long syscall2(size_t num, size_t a0, size_t a2) {
    long value;
    asm volatile("syscall" : "=a"(value) : "a"(num), "D"(a0), "S"(a2) : "memory", "rcx", "r11");
    return value;
}

static inline long syscall3(size_t num, size_t a0, size_t a2, size_t a3) {
    long value;
    asm volatile("syscall" : "=a"(value) : "a"(num), "D"(a0), "S"(a2), "d"(a3) : "memory", "rcx", "r11");
    return value;
}

static inline long syscall4(size_t num, size_t a0, size_t a1, size_t a2, size_t a3) {
    register size_t r10 asm("r10") = a3;

    long value;
    asm volatile("syscall" : "=a"(value) : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(r10) : "memory", "rcx", "r11");
    return value;
}

static inline long syscall5(size_t num, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4) {
    register size_t r10 asm("r10") = a3;
    register size_t r8 asm("r8") = a4;

    long value;
    asm volatile("syscall"
                 : "=a"(value)
                 : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8)
                 : "memory", "rcx", "r11");
    return value;
}

static inline long syscall6(size_t num, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    register size_t r10 asm("r10") = a3;
    register size_t r8 asm("r8") = a4;
    register size_t r9 asm("r9") = a5;

    long value;
    asm volatile("syscall"
                 : "=a"(value)
                 : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                 : "memory", "rcx", "r11");
    return value;
}
