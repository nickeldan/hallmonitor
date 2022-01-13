#ifndef HALLMONITOR_ARRAY_H
#define HALLMONITOR_ARRAY_H

#include <sys/types.h>

#include "definitions.h"

typedef struct hamoArray {
    void *data;
    size_t item_size;
    size_t length;
    size_t capacity;
} hamoArray;

#define HAMO_ARRAY(type)         \
    {                            \
        NULL, sizeof(type), 0, 0 \
    }

int
hamoArrayAppend(hamoArray *array, const void *item);

void
hamoArrayFree(hamoArray *array);

#define ARRAY_GET_ITEM(array, idx) ((void *)((unsigned char *)(array)->data + (idx) * (array)->item_size))

#define ARRAY_FOR_EACH(array, item)                                            \
    for (item = (array)->data; item != ARRAY_GET_ITEM(array, (array)->length); \
         item = (void *)((unsigned char *)item + (array)->item_size))

#endif  // HALLMONITOR_ARRAY_H
