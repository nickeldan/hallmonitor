#ifndef HALLMONITOR_CAPTURE_H
#define HALLMONITOR_CAPTURE_H

#include <pcap.h>

#include "definitions.h"

#define HAMO_MAX_BYTES_CAPTURED 512

/**
 * @brief Creates and activates a PCAP handle.
 * 
 * @param phandle_ptr A pointer to the handle to be created.
 * @param whitelist_file If not NULL, specifies a file containing whitelist information to include in the BPF.
 * 
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoPcapCreate(pcap_t **phandle_ptr, const char *whitelist_file);

/**
 * @brief Processes any captured packets.
 * 
 * @param phandle The PCAP handle.
 * 
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoPcapDispatch(pcap_t *phandle);

#endif // HALLMONITOR_CAPTURE_H