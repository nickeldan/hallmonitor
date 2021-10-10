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
    char *device;
    hamoPcap capturer = HAMO_PCAP_INIT;

    if ( argc == 1 ) {
        fprintf(stderr, "Missing device name\n");
        return HAMO_RET_USAGE;
    }
    device = argv[1];

    if ( hamoLoggerInit(LL_USE) != VASQ_RET_OK ) {
        return HAMO_RET_OUT_OF_MEMORY;
    }

    hamoJournalInit(HAMO_NULL_JOURNALER, NULL);

    ret = hamoPcapCreate(&capturer, device, NULL, 0);
    if ( ret != HAMO_RET_OK ) {
        return ret;
    }

    ret = hamoPcapDispatch(&capturer, -1, NULL);
    hamoPcapClose(&capturer);
    return ret;
}
