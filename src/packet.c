#include <stdint.h>
#include <string.h>

#include <hamo/journal.h>

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
#define TCP_ACK_FLAG        0x10

struct parseCtx {
    const hamoArray *journalers;
    unsigned int *count;
    int link_type;
};

static inline uint16_t
fetchU16(const uint8_t *src)
{
    return (src[0] << 8) | src[1];
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
        VASQ_ERROR(hamo_logger, "Unsupported data link type: %s", pcap_datalink_val_to_name(link_type));
        return (unsigned int)-1;
    }
}

static bool
parseIPv4Header(const uint8_t *header, unsigned int size, hamoRecord *record, unsigned int *so_far)
{
    unsigned int ihl, total_length;

    if (size < IPV4_MIN_HEADER_SIZE) {
        VASQ_WARNING(hamo_logger, "Not enough bytes captured");
        return false;
    }

    ihl = (header[IPV4_IHL_OFFSET] & 0x0f) * 4;
    if (ihl < IPV4_MIN_HEADER_SIZE) {
        VASQ_ERROR(hamo_logger, "Invalid internet header length: %u", ihl);
        return false;
    }
    *so_far += ihl;

    total_length = fetchU16(header + IPV4_TOTAL_LENGTH_OFFSET);
    if (total_length < ihl) {
        VASQ_ERROR(hamo_logger, "Invalid IPv4 total length: %u", total_length);
        return false;
    }
    else if (total_length > size) {
        VASQ_WARNING(hamo_logger, "Not enough bytes captured");
        return false;
    }

    if (header[IPV4_PROTOCOL_OFFSET] != IPV4_TCP_PROTOCOL) {
        VASQ_ERROR(hamo_logger, "We've somehow captured a non-TCP packet despite our BPF");
        return false;
    }

    memcpy(&record->saddr, header + IPV4_SRC_OFFSET, IPV4_SIZE);
    memcpy(&record->daddr, header + IPV4_DST_OFFSET, IPV4_SIZE);

    return true;
}

static bool
parseTCPHeader(const uint8_t *header, unsigned int size, hamoRecord *record)
{
    if (size < TCP_MIN_HEADER_SIZE) {
        VASQ_WARNING(hamo_logger, "Not enough bytes captured");
        return false;
    }

    if (!(header[TCP_FLAGS_OFFSET] & TCP_SYN_FLAG)) {
        VASQ_ERROR(hamo_logger, "We've somehow captured a non-SYN TCP packet despite our BPF");
        return false;
    }
    record->ack_flag = ((header[TCP_FLAGS_OFFSET] & TCP_ACK_FLAG) != 0);

    record->sport = fetchU16(header + TCP_SPORT_OFFSET);
    record->dport = fetchU16(header + TCP_DPORT_OFFSET);

    return true;
}

static void
parsePacket(u_char *user, const struct pcap_pkthdr *header, const u_char *data)
{
    unsigned int size = header->caplen, so_far;
    const struct parseCtx *ctx = (const struct parseCtx *)user;
    hamoRecord record = {0};

    VASQ_DEBUG(hamo_logger, "Captured %u bytes of a %u-byte packet", size, header->len);
    VASQ_HEXDUMP(hamo_logger, "Packet", data, size);

    so_far = determineLinkLayerSize(ctx->link_type, data, size);
    if (so_far == (unsigned int)-1) {
        VASQ_ERROR(hamo_logger, "We've somehow captured a packet using an unsupported link layer protocol");
        return;
    }

    if (size <= so_far) {
        VASQ_WARNING(hamo_logger, "Not enough bytes captured");
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
        VASQ_ERROR(hamo_logger, "We've somehow captured an IPv6 packet despite our BPF");
        return;
#endif

    default: VASQ_ERROR(hamo_logger, "Invalid IP version: %u", (data[so_far] >> 4)); return;
    }

    if (!parseTCPHeader(data + so_far, size - so_far, &record)) {
        return;
    }

    record.timestamp = header->ts;

    if (ctx->count) {
        (*ctx->count)++;
    }

    if (ctx->journalers) {
        void *item;

        ARRAY_FOR_EACH(ctx->journalers, item)
        {
            const hamoJournaler *journaler = item;

            journaler->func(journaler->user, &record);
        }
    }
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
hamoProcessPackets(pcap_t *handle, const hamoArray *journalers, unsigned int *count)
{
    struct parseCtx ctx;

    ctx.journalers = journalers;
    ctx.count = count;
    ctx.link_type = pcap_datalink(handle);

    if (pcap_dispatch(handle, -1, parsePacket, (u_char *)&ctx) == PCAP_ERROR) {
        VASQ_ERROR(hamo_logger, "pcap_dispatch: %s", pcap_geterr(handle));
    }
}
