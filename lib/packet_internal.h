#ifndef HALLMONITOR_PACKET_INTERNAL_H
#define HALLMONITOR_PACKET_INTERNAL_H

#include <stdbool.h>

#include <pcap.h>

#include <hamo/array.h>
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
 * @param handle The PCAP handle to use.
 * @param journalers An array of hamoJournalers (see hamo/journal.h)  to apply to any captured packets.
 */
void HIDDEN_SYMBOL
hamoProcessPacket(pcap_t *handle, const hamoArray *journalers);

#endif  // HALLMONITOR_PACKET_INTERNAL_H
