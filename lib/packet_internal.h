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
 * @brief Processes all available packets and writes them to the journal.
 *
 * @param phandle The PCAP handle to use.
 *
 * @return The number of packets handled or, if an error occurred, -1 times the error code.
 */
int HIDDEN_SYMBOL
hamoProcessPackets(pcap_t *phandle);

#endif  // HALLMONITOR_PACKET_INTERNAL_H