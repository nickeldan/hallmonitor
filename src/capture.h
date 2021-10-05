#ifndef HALLMONITOR_CAPTURE_H
#define HALLMONITOR_CAPTURE_H

#include <pcap.h>

#include "definitions.h"

#define HAMO_MAX_BYTES_CAPTURED 512

typedef struct hamoPcap {
    pcap_t *phandle;
    int fd;
} hamoPcap;

/**
 * @brief Creates and activates a PCAP handle.
 *
 * @param handle A pointer to the structure to be populated.
 * @param whitelist_file If not NULL, specifies a file containing whitelist information to include in the
 * BPF.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoPcapCreate(hamoPcap *handle, const char *whitelist_file);

/**
 * @brief Processes any captured packets.
 *
 * @param phandle The PCAP handle.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoPcapDispatch(pcap_t *phandle);

/**
 * @brief Frees any resources associated with a hamoPcap.
 *
 * @param handle A pointer to the hamoPcap.
 */
void
hamoPcapClose(hamoPcap *handle);

#endif  // HALLMONITOR_CAPTURE_H