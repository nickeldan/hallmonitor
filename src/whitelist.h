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
 * @param filename The path to the file containing the whitelist information.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoWhitelistLoad(const char *filename);

/**
 * @brief Fetches an entry from the whitelist.
 *
 * @param idx The desired index in the whitelist.
 *
 * @return A pointer to the entry or NULL if idx is greater than or equal to the number of entries.
 */
const hamoWhitelistEntry *
hamoWhitelistEntryFetch(size_t idx);

#endif  // HALLMONITOR_WHITELIST_H