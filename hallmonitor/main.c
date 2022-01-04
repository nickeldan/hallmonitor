#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <hamo/capture.h>
#include <hamo/definitions.h>
#include <hamo/journal.h>

#define TCP_ACK_FLAG 0x10

static void
printRecord(void *user, const hamoRecord *record)
{
    (void)user;
    int af = record->ipv6 ? AF_INET6 : AF_INET;
    char src_buffer[INET6_ADDRSTRLEN], dst_buffer[INET6_ADDRSTRLEN];
    const char *packet_type;

    inet_ntop(af, &record->source_address, src_buffer, sizeof(src_buffer));
    inet_ntop(af, &record->destination_address, dst_buffer, sizeof(src_buffer));

    packet_type = (record->tcp_flags & TCP_ACK_FLAG) ? "SYN-ACK" : "SYN";

    if (record->ipv6) {
        VASQ_INFO(hamo_logger, "%s packet sent from [%s]:%u to [%s]:%u", packet_type, src_buffer,
                  record->sport, dst_buffer, record->dport);
    }
    else {
        VASQ_INFO(hamo_logger, "%s packet sent from %s:%u to %s:%u", packet_type, src_buffer, record->sport,
                  dst_buffer, record->dport);
    }
}

int
main(int argc, char **argv)
{
    int ret;
    char *device;
    hamoDispatcher dispatcher = HAMO_DISPATCHER_INIT;
    hamoJournaler journaler = {.func = printRecord, .user = NULL};

    if (argc < 2) {
        fprintf(stderr, "Missing device name\n");
        return HAMO_RET_USAGE;
    }
    device = argv[1];

#ifndef LL_USE
#ifdef DEBUG
#define LL_USE VASQ_LL_DEBUG
#else
#define LL_USE VASQ_LL_INFO
#endif
#endif

#ifdef DEBUG
#define LOGGER_FORMAT "%t [%L]%_ %f:%l: %M\n"
#else
#define LOGGER_FORMAT "%t [%L]%_ %M\n"
#endif
    ret = vasqLoggerCreate(STDOUT_FILENO, LL_USE, LOGGER_FORMAT, NULL, &hamo_logger);
    if (ret != VASQ_RET_OK) {
        fprintf(stderr, "vasqLoggerCreate: %s\n", vasqErrorString(ret));
        return HAMO_RET_OUT_OF_MEMORY;
    }

    VASQ_INFO(hamo_logger, "Running Hallmonitor %s", HAMO_VERSION);

    ret = hamoArrayAppend(&dispatcher.journalers, &journaler);
    if (ret != HAMO_RET_OK) {
        goto done;
    }

    ret = hamoPcapAdd(&dispatcher.handles, device, NULL);
    if (ret != HAMO_RET_OK) {
        goto done;
    }

    VASQ_INFO(hamo_logger, "Beginning packet capturing");

    while ((ret = hamoPcapDispatch(&dispatcher, -1)) == HAMO_RET_OK) {}

done:
    hamoDispatcherFree(&dispatcher);
    vasqLoggerFree(hamo_logger);

    return ret;
}
