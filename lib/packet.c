#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "journal_internal.h"
#include "packet_internal.h"

#define IPV4_MIN_HEADER_SIZE     20
#define IPV4_IHL_OFFSET          0
#define IPV4_TOTAL_LENGTH_OFFSET 2
#define IPV4_PROTOCOL_OFFSET     9
#define IPV4_TCP_PROTOCOL        0x06
#define IPV4_SRC_OFFSET          12
#define IPV4_DST_OFFSET          16

#define TCP_MIN_HEADER_SIZE 20
#define TCP_SPORT_OFFSET    0
#define TCP_DPORT_OFFSET    2
#define TCP_FLAGS_OFFSET    13
#define TCP_SYN_FLAG        0x02

static inline uint16_t
fetchU16(const uint8_t *src)
{
    return (src[0] << 8) + src[1];
}

static unsigned int
determineLinkLayerSize(int link_type, const uint8_t *data, unsigned int size)
{
    (void)data;
    (void)size;

    if (link_type == DLT_EN10MB) {
        return 14;
    }
    else if (link_type == DLT_LINUX_SLL) {
        return 16;
    }
    /*
        else if ( link_type == DLT_IEEE802_11 ) {
        }
    */
    else {
        VASQ_ERROR(logger, "Unsupported data link type: %s", pcap_datalink_val_to_name(link_type));
        return (unsigned int)-1;
    }
}

static bool
parseIPv4Header(const uint8_t *header, unsigned int size, hamoRecord *record, unsigned int *so_far)
{
    unsigned int ihl, total_length;

    if (size < IPV4_MIN_HEADER_SIZE) {
        VASQ_ERROR(logger, "Not enough bytes captured");
        return false;
    }

    ihl = (header[IPV4_IHL_OFFSET] & 0x0f) * 4;
    if (ihl < IPV4_MIN_HEADER_SIZE) {
        VASQ_ERROR(logger, "Invalid internet header length: %u", ihl);
        return false;
    }
    *so_far += ihl;

    total_length = fetchU16(header + IPV4_TOTAL_LENGTH_OFFSET);
    if (total_length < ihl) {
        VASQ_ERROR(logger, "Invalid IPv4 total length: %u", total_length);
        return false;
    }
    else if (total_length > size) {
        VASQ_ERROR(logger, "Not enough bytes captured");
        return false;
    }

    if (header[IPV4_PROTOCOL_OFFSET] != IPV4_TCP_PROTOCOL) {
        VASQ_ERROR(logger, "We've somehow captured a non-TCP packet despite our BPF");
        return false;
    }

    memcpy(&record->source_address, header + IPV4_SRC_OFFSET, IPV4_SIZE);
    memcpy(&record->destination_address, header + IPV4_DST_OFFSET, IPV4_SIZE);

    return true;
}

static bool
parseTCPHeader(const uint8_t *header, unsigned int size, hamoRecord *record)
{
    if (size < TCP_MIN_HEADER_SIZE) {
        VASQ_WARNING(logger, "Not enough bytes captured");
        return false;
    }

    if (!(header[TCP_FLAGS_OFFSET] & TCP_SYN_FLAG)) {
        VASQ_ERROR(logger, "We've somehow captured a non-SYN TCP packet despite our BPF");
        return false;
    }
    record->tcp_flags = header[TCP_FLAGS_OFFSET];

    record->sport = fetchU16(header + TCP_SPORT_OFFSET);
    record->dport = fetchU16(header + TCP_DPORT_OFFSET);

    return true;
}

static void
parsePacket(u_char *user, const struct pcap_pkthdr *header, const u_char *data)
{
    unsigned int size = header->caplen, so_far;
    int link_type = (intptr_t)user;
    hamoRecord record = {0};

    VASQ_DEBUG(logger, "Captured %u bytes of a %u-byte packet", size, header->len);
    VASQ_HEXDUMP(logger, "Packet", data, size);

    so_far = determineLinkLayerSize(link_type, data, size);
    if (so_far == (unsigned int)-1) {
        return;
    }

    if (size <= so_far) {
        VASQ_WARNING(logger, "Not enough bytes captured");
        return;
    }

    switch (data[so_far] >> 4) {
    case 4:
        if (!parseIPv4Header(data + so_far, size - so_far, &record, &so_far)) {
            return;
        }
        break;

    case 6:
#ifdef HAMO_IPV6_SUPPORTED
        ctx->record.ip6 = true;
        if (!parseIPv6Header(data + so_far, size - so_far, &record, &so_far)) {
            return;
        }
        break;
#else
        VASQ_ERROR(logger, "We've somehow captured an IPv6 packet despite our BPF");
        return;
#endif

    default: VASQ_ERROR(logger, "Invalid IP version: %u", (data[so_far] >> 4)); return;
    }

    if (!parseTCPHeader(data + so_far, size - so_far, &record)) {
        return;
    }

    record.timestamp = header->ts;

    hamoJournalWrite(&record);
}

bool
hamoLinkTypeSupported(int link_type)
{
    switch (link_type) {
    case DLT_EN10MB:
    // case DLT_IEEE802_11:
    case DLT_LINUX_SLL: return true;

    default: return false;
    }
}

void
hamoProcessPacket(pcap_t *phandle)
{
    int link_type;

    if (!phandle) {
        VASQ_ERROR(logger, "phandle cannot be NULL");
        return;
    }

    link_type = pcap_datalink(phandle);

    if (pcap_dispatch(phandle, 1, parsePacket, (u_char *)(intptr_t)link_type) == PCAP_ERROR) {
        VASQ_ERROR(logger, "pcap_dispatch: %s", pcap_geterr(phandle));
    }
}
