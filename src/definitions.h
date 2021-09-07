#ifndef HALLMONITOR_DEFINITIONS_H
#define HALLMONITOR_DEFINITIONS_H

#include <vasq/logger.h>
#include <vasq/placeholder.h>

#define IPV4_SIZE 4
#define IPV6_SIZE 16

enum hamoRetValue {
    HAMO_RET_OK = 0,
    HAMO_RET_USAGE,
    HAMO_RET_PCAP_LOOKUP_DEVICE,
    HAMO_RET_PCAP_OPEN,
    HAMO_RET_PCAP_SET_DATALINK,
};

/**
 * @brief Initializes the logger.
 * 
 * @return VASQ_RET_OK if successful and an error code otherwise.
 */
int
hamoLoggerInit(void);

extern vasqLogger *logger;

#endif