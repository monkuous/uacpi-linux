#pragma once

#include <stddef.h>

void *allocate(size_t size);
void free(void *ptr, size_t size);
