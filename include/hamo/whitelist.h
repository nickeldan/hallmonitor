#ifndef HALLMONITOR_WHITELIST_H
#define HALLMONITOR_WHITELIST_H

#include <stdint.h>
#include <stdio.h>

#include "array.h"
#include "definitions.h"

typedef struct hamoWhitelistEntry {
    char *saddr;
    char *daddr;
    uint16_t dport;
    unsigned int ipv6 : 1;
} hamoWhitelistEntry;

/**
 * @brief Frees any data associated with a whitelist entry.
 *
 * @param entry A pointer to the entry.
 */
void
hamoWhitelistEntryFree(hamoWhitelistEntry *entry);

/**
 * @brief Parses a whitelist entry from a string.
 *
 * @param string The string.
 * @param entry A pointer to the entry to be populated.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoWhitelistEntryParse(const char *string, hamoWhitelistEntry *entry);

/**
 * @brief Initializes the whitelist from a file.
 *
 * @param file A file handle opened for reading.
 * @param entries A pointer to an array of hamoWhitelistEntries.  The entries read from the file will be
 *                appended to the array.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoWhitelistLoad(FILE *file, hamoArray *entries);

/**
 * @brief Frees whitelist entries contained in an array.
 *
 * @param entries A pointer to the array.
 */
void
hamoWhitelistFree(hamoArray *entries);

#endif  // HALLMONITOR_WHITELIST_H
