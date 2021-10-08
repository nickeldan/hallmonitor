#ifndef HALLMONITOR_JOURNAL_H
#define HALLMONITOR_JOURNAL_H

#include <stdint.h>

#include "definitions.h"

typedef struct hamoRecord {
    uint16_t sport;
    uint16_t dport;
    uint8_t source_address[IPV6_SIZE];
    uint8_t destination_address[IPV6_SIZE];
    unsigned int ipv6 : 1;
    unsigned int ack_flag : 1;
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
 * @brief Passing this function to hamoJournalInit will cause nothing to happen when a record is written.
 */
#define HAMO_NULL_JOURNALER (hamoJournaler) NULL

/**
 * @brief Initializes journaling.
 *
 * @param journaler The journaling function to use.
 * @param user A pointer which will be passed to the journaler when called.
 */
void
hamoJournalInit(hamoJournaler journaler, void *user);

/**
 * @brief Writes a packet capture record to the journal.
 *
 * @param record A pointer to the record.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoJournalWrite(const hamoRecord *record);

#endif  // HALLMONITOR_JOURNAL_H