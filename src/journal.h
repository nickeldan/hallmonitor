#ifndef HALLMONITOR_JOURNAL_H
#define HALLMONITOR_JOURNAL_H

#include <stdint.h>
#include <time.h>

#include "definitions.h"

typedef struct hamoRecord {
    time_t timestamp;
    uint16_t sport;
    uint16_t dport;
    uint8_t source_address[IPV6_SIZE];
    uint8_t destination_address[IPV6_SIZE];
    unsigned int ipv6:1;
} hamoRecord;

/**
 * @brief Initializes journaling.
 * 
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoJournalInit(void);

/**
 * @brief Writes a packet capture record to the journal.
 * 
 * @param record A pointer to the record.
 * 
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoJournalWrite(const hamoRecord *record);

#endif // HALLMONITOR_JOURNAL_H