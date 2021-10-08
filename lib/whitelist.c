#include <stdlib.h>

#include <hamo/whitelist.h>

int
hamoWhitelistLoad(const char *filename, hamoWhitelistEntry **entries, size_t *num_entries)
{
    if (!entries || !num_entries) {
        VASQ_ERROR(logger, "entries and num_entries cannot be NULL");
        return HAMO_RET_USAGE;
    }

    if (!filename) {
        VASQ_DEBUG(logger, "Not using a whitelist file");
        *entries = NULL;
        *num_entries = 0;
        return HAMO_RET_OK;
    }

    VASQ_DEBUG(logger, "Using the whitelist file %s", filename);

    PLACEHOLDER();
    return HAMO_RET_USAGE;
}

void
hamoWhitelistFree(hamoWhitelistEntry *entries)
{
    free(entries);
}