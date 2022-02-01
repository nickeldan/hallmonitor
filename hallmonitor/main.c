#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <hamo/hamo.h>
#include <hamo/journal.h>
#include <hamo/whitelist.h>

static volatile sig_atomic_t signal_caught;

static void
usage(const char *exec)
{
    printf("Usage: %s [-d <network device>]* [-w <whitelist file>]* [-v] [-h]\n", exec);
}

static void
signalHandler(int signum)
{
    (void)signum;
    signal_caught = true;
}

static void
printRecord(void *user, const hamoRecord *record)
{
    (void)user;
    int af = record->ipv6 ? AF_INET6 : AF_INET;
    char src_buffer[INET6_ADDRSTRLEN], dst_buffer[INET6_ADDRSTRLEN];
    const char *packet_type;

    inet_ntop(af, &record->source_address, src_buffer, sizeof(src_buffer));
    inet_ntop(af, &record->destination_address, dst_buffer, sizeof(dst_buffer));

    packet_type = (record->ack_flag) ? "SYN-ACK" : "SYN";

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
    int ret, option;
    vasqLogLevel_t level = VASQ_LL_INFO;
    const char *format_string = "%t [%L]%_ %M\n";
    void *item;
    struct sigaction action = {.sa_handler = signalHandler};
    hamoArray devices = HAMO_ARRAY(const char *);
    hamoArray whitelist_entries = HAMO_ARRAY(hamoWhitelistEntry);
    hamoDispatcher dispatcher = HAMO_DISPATCHER_INIT;
    hamoJournaler journaler = {.func = printRecord, .user = NULL};

    while ((option = getopt(argc, argv, "d:w:vh")) != -1) {
        switch (option) {
        case 'v':
            level = VASQ_LL_DEBUG;
            format_string = "%t [%L]%_ %f:%l: %M\n";
            break;

        case 'd':
        case 'w': break;

        case 'h': usage(argv[0]); return HAMO_RET_OK;

        default: usage(argv[0]); return HAMO_RET_USAGE;
        }
    }

    ret = vasqLoggerCreate(STDOUT_FILENO, level, format_string, NULL, &hamo_logger);
    if (ret != VASQ_RET_OK) {
        fprintf(stderr, "vasqLoggerCreate: %s\n", vasqErrorString(ret));
        return HAMO_RET_OUT_OF_MEMORY;
    }

    VASQ_INFO(hamo_logger, "Running Hall Monitor %s", HAMO_VERSION);

    optind = 1;
    while ((option = getopt(argc, argv, "d:w:vh")) != -1) {
        switch (option) {
            FILE *f;

        case 'd':
            ret = hamoArrayAppend(&devices, &optarg);
            if (ret != HAMO_RET_OK) {
                goto done;
            }
            break;

        case 'w':
            f = fopen(optarg, "r");
            if (!f) {
                VASQ_PERROR(hamo_logger, "Could not read from whitelist file", errno);
                ret = HAMO_RET_BAD_WHITELIST;
                goto done;
            }
            ret = hamoWhitelistLoad(f, &whitelist_entries);
            fclose(f);
            if (ret != HAMO_RET_OK) {
                goto done;
            }
            break;
        }
    }

    ret = hamoArrayAppend(&dispatcher.journalers, &journaler);
    if (ret != HAMO_RET_OK) {
        goto done;
    }

    if (devices.length > 0) {
        ARRAY_FOR_EACH(&devices, item)
        {
            ret = hamoDeviceAdd(&dispatcher, *(const char **)item, &whitelist_entries);
            if (ret != HAMO_RET_OK) {
                goto done;
            }
        }
        hamoArrayFree(&devices);
    }
    else {
        ret = hamoDeviceAdd(&dispatcher, "any", &whitelist_entries);
        if (ret != HAMO_RET_OK) {
            goto done;
        }
    }
    hamoArrayFree(&whitelist_entries);

    sigfillset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);

    VASQ_INFO(hamo_logger, "Beginning packet capturing");

    while ((ret = hamoCaptureDispatch(&dispatcher, -1, NULL)) == HAMO_RET_OK && !signal_caught) {}

done:
    hamoDispatcherFree(&dispatcher);
    hamoArrayFree(&devices);
    hamoArrayFree(&whitelist_entries);
    vasqLoggerFree(hamo_logger);

    return ret;
}
