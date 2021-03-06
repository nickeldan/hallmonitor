#include <stdlib.h>
#include <string.h>

#include <hamo/array.h>

#define INITIAL_CAPACITY         1
#define CAPACITY_EXPANSION(size) ((size) + 2)

int
hamoArrayAppend(hamoArray *array, const void *item)
{
    if (!array || !item) {
        VASQ_ERROR(hamo_logger, "The arguments cannot be NULL");
        return HAMO_RET_USAGE;
    }

    if (array->item_size == 0) {
        VASQ_ERROR(hamo_logger, "The array's item_size cannot be 0");
        return HAMO_RET_USAGE;
    }

    if (array->length == array->capacity) {
        size_t new_capacity =
            (array->capacity == 0) ? INITIAL_CAPACITY : CAPACITY_EXPANSION(array->capacity);
        void *success;

        success = realloc(array->data, new_capacity * array->item_size);
        if (!success) {
            return HAMO_RET_OUT_OF_MEMORY;
        }

        array->data = success;
        array->capacity = new_capacity;
    }

    memcpy(array->data + array->length * array->item_size, item, array->item_size);
    array->length++;

    return HAMO_RET_OK;
}

void
hamoArrayFree(hamoArray *array)
{
    if (!array) {
        return;
    }

    free(array->data);
    array->data = NULL;
    array->length = array->capacity = 0;
}
