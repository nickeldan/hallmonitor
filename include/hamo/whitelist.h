#ifndef HALLMONITOR_WHITELIST_H
#define HALLMONITOR_WHITELIST_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "array.h"
#include "definitions.h"

typedef struct hamoWhitelistEntry {
    uint16_t port;
    char saddr[INET6_ADDRSTRLEN];
    char daddr[INET6_ADDRSTRLEN];
} hamoWhitelistEntry;

#define IPV6_ENTRY(entry) (strchr((entry)->saddr, ':') || strchr((entry)->daddr, ':'))

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

#endif  // HALLMONITOR_WHITELIST_H
