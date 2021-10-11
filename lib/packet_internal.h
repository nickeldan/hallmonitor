#ifndef HALLMONITOR_PACKET_INTERNAL_H
#define HALLMONITOR_PACKET_INTERNAL_H

#include <stdbool.h>

#include <pcap.h>

#include <hamo/definitions.h>

/**
 * Is a data link type supported?
 *
 * @param link_type The link type.
 *
 * @return true if supported and false otherwise.
 */
bool HIDDEN_SYMBOL
hamoLinkTypeSupported(int link_type);

/**
 * @brief Processes at most one packet and writes it to the journal.
 *
 * @param phandle The PCAP handle to use.
 */
void HIDDEN_SYMBOL
hamoProcessPacket(pcap_t *phandle);

#endif  // HALLMONITOR_PACKET_INTERNAL_H