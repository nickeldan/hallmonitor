#include "capture.h"
#include "whitelist.h"

#define HAMO_BPF_MAX_SIZE 1024

static int
setBpf(pcap_t *phandle, const char *whitelist_file)
{
    int ret;
    char bpf[HAMO_BPF_MAX_SIZE] = "tcp[tcpflags] & (tcp-syn) != 0";

    ret = hamoWhitelistLoad(whitelist_file);
    if ( ret != HAMO_RET_OK ) {
        return ret;
    }

    PLACEHOLDER();
    return HAMO_RET_USAGE;
}

int
hamoPcapCreate(pcap_t **phandle_ptr, const char *whitelist_file) {
    int ret;
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if ( !phandle_ptr ) {
        VASQ_ERROR(logger, "phandle_ptr cannot be NULL");
        return HAMO_RET_USAGE;
    }

    device = pcap_lookupdev(errbuf);
    if ( !device ) {
        VASQ_ERROR(logger, "pcap_lookupdev: %s\n", errbuf);
        return HAMO_RET_PCAP_LOOKUP_DEVICE;
    }

    VASQ_DEBUG(logger, "Capturing on: %s\n", device);

    *phandle_ptr = pcap_open_live(device, HAMO_MAX_BYTES_CAPTURED, true, 1000, errbuf);
    if ( !*phandle_ptr ) {
        VASQ_ERROR(logger, "pcap_open_live: %s", errbuf);
        return HAMO_RET_PCAP_OPEN;
    }

    if ( pcap_set_datalink(*phandle_ptr, DLT_LINUX_SLL) == -1 ) {
        VASQ_ERROR(logger, "Failed to set data link type to DLT_LINUX_SLL");
        ret = HAMO_RET_PCAP_SET_DATALINK;
        goto error;
    }

    ret = setBpf(*phandle_ptr, whitelist_file);
    if ( ret != HAMO_RET_OK ) {
        goto error;
    }

    return HAMO_RET_OK;

error:

    pcap_close(*phandle_ptr);
    return ret;
}