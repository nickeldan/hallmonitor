#ifndef HALLMONITOR_JOURNAL_H
#define HALLMONITOR_JOURNAL_H

#include <stdint.h>
#include <sys/time.h>

#include "definitions.h"

typedef struct hamoRecord {
    struct timeval timestamp;
    uint16_t sport;
    uint16_t dport;
    uint8_t source_address[IPV6_SIZE];
    uint8_t destination_address[IPV6_SIZE];
    uint8_t tcp_flags;
    unsigned int ipv6 : 1;
} hamoRecord;

/**
 * @brief Type for a function which journals a captured packet record.
 *
 * @param record A pointer to the record.
 * @param user User-supplied data (see hamoJournalInit below).
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
typedef int (*hamoJournaler)(const hamoRecord *record, void *user);

/**
 * @brief Initializes journaling.
 *
 * @param journaler The journaling function to use.
 * @param user A pointer which will be passed to the journaler when called.  If NULL, then a journaler which
    does nothing will be used.
 */
void
hamoJournalInit(hamoJournaler journaler, void *user);

#endif  // HALLMONITOR_JOURNAL_H
