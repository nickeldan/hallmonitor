#ifndef HALLMONITOR_WHITELIST_H
#define HALLMONITOR_WHITELIST_H

#include <stdint.h>
#include <sys/types.h>

#include "definitions.h"

typedef struct hamoWhitelistEntry {
    const char *saddr;
    const char *dstaddr;
    uint16_t dport;
    unsigned int ipv6 : 1;
} hamoWhitelistEntry;

/**
 * @brief Initializes the whitelist from a file.
 *
 * @param filename The path to the file containing the whitelist information.  If NULL, then an empty list
 * will be created.
 * @param entries A pointer to a entry array to be allocated.
 * @param num_entries A pointer to number of entries.  Will be set by this function.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoWhitelistLoad(const char *filename, hamoWhitelistEntry **entries, size_t *num_entries);

void
hamoWhitelistFree(hamoWhitelistEntry *entries);

#endif  // HALLMONITOR_WHITELIST_H