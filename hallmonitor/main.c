#include <stdio.h>
#include <unistd.h>

#include <hamo/capture.h>
#include <hamo/definitions.h>
#include <hamo/journal.h>

#ifndef LL_USE
#ifdef DEBUG
#define LL_USE VASQ_LL_DEBUG
#else
#define LL_USE VASQ_LL_INFO
#endif
#endif

#define TCP_ACK_FLAG 0x10

static int
printRecord(const hamoRecord *record, void *user)
{
    (void)user;
    int af = record->ipv6 ? AF_INET6 : AF_INET;
    char src_buffer[INET6_ADDRSTRLEN], dst_buffer[INET6_ADDRSTRLEN];
    const char *packet_type;

    inet_ntop(af, &record->source_address, src_buffer, sizeof(src_buffer));
    inet_ntop(af, &record->destination_address, dst_buffer, sizeof(src_buffer));

    packet_type = (record->tcp_flags & TCP_ACK_FLAG) ? "SYN-ACK" : "SYN";

    if (record->ipv6) {
        VASQ_INFO(logger, "%s packet sent from [%s]:%u to [%s]:%u", packet_type, src_buffer, record->sport,
                  dst_buffer, record->dport);
    }
    else {
        VASQ_INFO(logger, "%s packet sent from %s:%u to %s:%u", packet_type, src_buffer, record->sport,
                  dst_buffer, record->dport);
    }

    return HAMO_RET_OK;
}

int
main(int argc, char **argv)
{
    int ret;
    char *device;
    hamoPcap capturer = HAMO_PCAP_INIT;

    if (argc < 2) {
        fprintf(stderr, "Missing device name\n");
        return HAMO_RET_USAGE;
    }
    device = argv[1];

    if (hamoLoggerInit(STDOUT_FILENO, LL_USE) != VASQ_RET_OK) {
        return HAMO_RET_OUT_OF_MEMORY;
    }

    hamoJournalInit(printRecord, NULL);

    ret = hamoPcapCreate(&capturer, device, NULL, 0);
    if (ret != HAMO_RET_OK) {
        return ret;
    }

    while ((ret = hamoPcapDispatch(&capturer, 1, -1)) == HAMO_RET_OK) {}

    hamoPcapClose(&capturer);
    return ret;
}
