#include <stdbool.h>
#include <string.h>

#include "capture.h"
#include "whitelist.h"

#define HAMO_BPF_MAX_SIZE 1024

#define BUFFER_WRITE_CHECK(format, ...)                                           \
    do {                                                                          \
        len += snprintf(bpf + len, sizeof(bpf) - len, format, ##__VA_ARGS__);     \
        if (len >= sizeof(bpf)) {                                                 \
            VASQ_ERROR(logger, "BPF is too long (%zu characters at least)", len); \
            return HAMO_RET_OVERFLOW;                                             \
        }                                                                         \
    } while (0)

static int
setBpf(pcap_t *phandle, const char *device, const char *whitelist_file)
{
    int ret;
    size_t len;
    bpf_u_int32 netp, maskp;
    char errbuf[PCAP_ERRBUF_SIZE], bpf[HAMO_BPF_MAX_SIZE] = "tcp[tcpflags] & (tcp-syn) != 0 and dst net ";
    const hamoWhitelistEntry *entry;
    struct bpf_program program;

    len = strnlen(bpf, sizeof(bpf));
    if (len >= sizeof(bpf)) {
        VASQ_CRITICAL(logger, "BPF buffer is too small");
        return HAMO_RET_OVERFLOW;
    }

    if (pcap_lookupnet(device, &netp, &maskp, errbuf) != 0) {
        VASQ_ERROR(logger, "pcap_lookupnet: %s", errbuf);
        return HAMO_RET_PCAP_LOOKUP_NET;
    }

#define GET_BYTE(n) ((unsigned char *)&netp)[n]
    BUFFER_WRITE_CHECK("%u.%u.%u.%u", GET_BYTE(0), GET_BYTE(1), GET_BYTE(2), GET_BYTE(3));
#undef GET_BYTE

    ret = hamoWhitelistLoad(whitelist_file);
    if (ret != HAMO_RET_OK) {
        return ret;
    }

    for (size_t k = 0; entry = hamoWhitelistEntryFetch(k); k++) {
        bool already_params = false;

        if (entry->ipv6) {
            VASQ_WARNING(logger,
                         "Skipping whitelist entry %zu because IPv6 addresses are not currently supported",
                         k);
            continue;
        }

        BUFFER_WRITE_CHECK(" and not (");

        if (entry->saddr) {
            BUFFER_WRITE_CHECK("src host %s", entry->saddr);
            already_params = true;
        }

        if (entry->dstaddr) {
            if (already_params) {
                BUFFER_WRITE_CHECK(" and ");
            }
            else {
                already_params = true;
            }

            BUFFER_WRITE_CHECK("dst host %s", entry->saddr);
        }

        if (entry->dport != 0) {
            if (already_params) {
                BUFFER_WRITE_CHECK(" and ");
            }

            BUFFER_WRITE_CHECK("dst port %u", entry->dport);
        }

        BUFFER_WRITE_CHECK(")");
    }

    VASQ_DEBUG("BPF: %s", bpf);

    if (pcap_compile(phandle, &program, bpf, true, 0) != 0) {
        VASQ_ERROR(logger, "pcap_compile: %s", pcap_geterr(phandle));
        return HAMO_RET_PCAP_COMPILE;
    }

    ret = pcap_setfilter(phandle, &program);
    pcap_freecode(&program);
    if (ret == 0) {
        ret = HAMO_RET_OK;
    }
    else {
        VASQ_ERROR(logger, "pcap_setfilter: %s", pcap_geterr(phandle));
        ret = HAMO_RET_PCAP_SET_FILTER;
    }

    return ret;
}

#undef BUFFER_WRITE_CHECK

int
hamoPcapCreate(hamoPcap *handle, const char *whitelist_file)
{
    int ret;
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!handle) {
        VASQ_ERROR(logger, "handle cannot be NULL");
        return HAMO_RET_USAGE;
    }

    *handle = (hamoPcap){0};

    device = pcap_lookupdev(errbuf);
    if (!device) {
        VASQ_ERROR(logger, "pcap_lookupdev: %s\n", errbuf);
        return HAMO_RET_PCAP_LOOKUP_DEVICE;
    }

    VASQ_DEBUG(logger, "Capturing on: %s\n", device);

    handle->phandle = pcap_open_live(device, HAMO_MAX_BYTES_CAPTURED, true, 1000, errbuf);
    if (!handle->phandle) {
        VASQ_ERROR(logger, "pcap_open_live: %s", errbuf);
        return HAMO_RET_PCAP_OPEN;
    }

    if (pcap_set_datalink(handle->phandle, DLT_LINUX_SLL) == -1) {
        VASQ_ERROR(logger, "Failed to set data link type to DLT_LINUX_SLL");
        ret = HAMO_RET_PCAP_SET_DATALINK;
        goto error;
    }

    ret = setBpf(handle->phandle, device, whitelist_file);
    if (ret != HAMO_RET_OK) {
        goto error;
    }

    handle->fd = pcap_get_selectable_fd(handle->phandle);
    if (handle->fd == PCAP_ERROR) {
        VASQ_ERROR(logger, "No selectable file descriptor associated with PCAP handle");
        ret = HAMO_RET_PCAP_NO_FD;
        goto error;
    }

    if (pcap_setnonblock(handle->phandle, true, errbuf) != 0) {
        VASQ_ERROR("pcap_setnonblock: %s", errbuf);
        ret = HAMO_RET_PCAP_SET_NONBLOCK;
        goto error;
    }

    return HAMO_RET_OK;

error:

    hamoPcapClose(handle);
    return ret;
}

void
hamoPcapClose(hamoPcap *handle)
{
    if (handle) {
        pcap_close(handle->phandle);
        *handle = (hamoPcap){0};
    }
}