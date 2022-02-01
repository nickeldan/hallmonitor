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
    unsigned int ipv6 : 1;
    unsigned int ack_flag : 1;
} hamoRecord;

typedef struct hamoJournaler {
    void (*func)(void *, const hamoRecord *);
    void *user;
} hamoJournaler;

#endif  // HALLMONITOR_JOURNAL_H
