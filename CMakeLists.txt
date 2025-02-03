cmake_minimum_required(VERSION 3.28)
project(uacpi-linux VERSION 0.1.0 LANGUAGES C)

include(uacpi/uacpi.cmake)

add_executable(uacpi-linux ${UACPI_SOURCES} heap.c main.c osl.c)
target_compile_definitions(uacpi-linux PRIVATE -DUACPI_SIZED_FREES)
target_compile_options(uacpi-linux PRIVATE -ffreestanding -fno-pie -fno-stack-protector)
target_link_options(uacpi-linux PRIVATE -nostdlib -static)
target_include_directories(uacpi-linux PRIVATE ${UACPI_INCLUDES})
