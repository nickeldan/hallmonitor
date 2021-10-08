#include <stdio.h>

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

int main(int argc, char **argv) {
    int ret;
    char *device, *whitelist_file;
    hamoPcap capturer = HAMO_PCAP_INIT;

    if ( argc == 1 ) {
        fprintf(stderr, "Missing device name\n");
        return HAMO_RET_USAGE;
    }
    device = argv[1];

    whitelist_file = (argc == 2)? NULL : argv[2];

    ret = hamoLoggerInit(LL_USE);
    if ( ret != VASQ_RET_OK ) {
        return -1*ret;
    }

    hamoJournalInit(HAMO_NULL_JOURNALER, NULL);

    ret = hamoPcapCreate(&capturer, device, whitelist_file);
    if ( ret != HAMO_RET_OK ) {
        return ret;
    }

    ret = hamoPcapDispatch(&capturer, -1, NULL);
    hamoPcapClose(&capturer);
    return ret;
}