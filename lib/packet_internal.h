#ifndef HALLMONITOR_PACKET_INTERNAL_H
#define HALLMONITOR_PACKET_INTERNAL_H

#include <stdbool.h>

#include <pcap.h>

#include <hamo/array.h>
#include <hamo/definitions.h>

#define HIDDEN_SYMBOL __attribute__((visibility("hidden")))

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
 * @param journalers An array of hamoJournalers (see hamo/journal.h) to apply to any captured packets.
 * @param count If not NULL, a pointer to an integer which will be increased by the number of packets
 * successfully parsed.
 */
void HIDDEN_SYMBOL
hamoProcessPacket(pcap_t *handle, const hamoArray *journalers, unsigned int *count);

#endif  // HALLMONITOR_PACKET_INTERNAL_H
