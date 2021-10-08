#ifndef HALLMONITOR_DEFINITIONS_H
#define HALLMONITOR_DEFINITIONS_H

#include <vasq/logger.h>
#include <vasq/placeholder.h>

//#define HAMO_IPV6_SUPPORTED

#define IPV4_SIZE 4
#define IPV6_SIZE 16

enum hamoRetValue {
    HAMO_RET_OK = 0,
    HAMO_RET_USAGE,
    HAMO_RET_OTHER,
    HAMO_RET_OUT_OF_MEMORY,
    HAMO_RET_OVERFLOW,
    HAMO_RET_PCAP_LOOKUP_DEVICE,
    HAMO_RET_PCAP_LOOKUP_NET,
    HAMO_RET_PCAP_OPEN,
    HAMO_RET_PCAP_DATALINK_UNSUPPORTED,
    HAMO_RET_PCAP_COMPILE,
    HAMO_RET_PCAP_SET_FILTER,
    HAMO_RET_PCAP_NO_FD,
    HAMO_RET_PCAP_SET_NONBLOCK,
    HAMO_RET_PCAP_NEXT,
    HAMO_RET_POLL_FAILED,
    HAMO_RET_NO_PACKETS_AVAILABLE,
    HAMO_RET_BAD_PACKET,
};

/**
 * @brief Initializes the logger.
 *
 * @param level The maximum log level to use.
 *
 * @return VASQ_RET_OK if successful and an error code otherwise.
 */
int
hamoLoggerInit(vasqLogLevel_t level);

extern vasqLogger *logger;

#endif