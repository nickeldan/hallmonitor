#ifndef HALLMONITOR_PACKET_H
#define HALLMONITOR_PACKET_H

#include <stdbool.h>

#include <pcap.h>

#include "definitions.h"

/**
 * Is a data link type supported?
 *
 * @param link_type The link type.
 *
 * @return true if supported and false otherwise.
 */
bool
hamoLinkTypeSupported(int link_type);

/**
 * @brief Processes a packet and writes it to the journal.
 *
 * @param phandle The PCAP handle to use.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoProcessPacket(pcap_t *phandle);

#endif  // HALLMONITOR_PACKET_H