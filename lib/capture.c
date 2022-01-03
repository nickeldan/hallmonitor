#include <alloca.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <hamo/capture.h>
#include <hamo/whitelist.h>

#include "packet_internal.h"

#define HAMO_BPF_MAX_SIZE       1024
#define HAMO_MAX_BYTES_CAPTURED 512

#define BUFFER_WRITE_CHECK(format, ...)                                           \
    do {                                                                          \
        len += snprintf(bpf + len, sizeof(bpf) - len, format, ##__VA_ARGS__);     \
        if (len >= sizeof(bpf)) {                                                 \
            VASQ_ERROR(logger, "BPF is too long (%zu characters at least)", len); \
            return HAMO_RET_OVERFLOW;                                             \
        }                                                                         \
    } while (0)

static int
setBpf(pcap_t *handle, const char *device, const hamoArray *whitelist)
{
    int ret;
    size_t len;
    bpf_u_int32 netp, maskp;
    unsigned int mask_size;
    char errbuf[PCAP_ERRBUF_SIZE], bpf[HAMO_BPF_MAX_SIZE] = "tcp[tcpflags] & (tcp-syn) != 0";
    struct bpf_program program;

    len = strnlen(bpf, sizeof(bpf));
    if (len >= sizeof(bpf)) {
        VASQ_CRITICAL(logger, "BPF buffer is too small");
        return HAMO_RET_OVERFLOW;
    }

#ifdef HAMO_IPV6_SUPPORTED
#error "IPv6 is not currently supported."
#endif

    if (pcap_lookupnet(device, &netp, &maskp, errbuf) != 0) {
        VASQ_ERROR(logger, "pcap_lookupnet: %s", errbuf);
        return HAMO_RET_PCAP_LOOKUP_NET;
    }

    maskp = ntohl(maskp);
    for (mask_size = 0; mask_size < 32; mask_size++) {
        if (!((maskp >> (31 - mask_size)) & 0x1)) {
            break;
        }
    }

#define GET_BYTE(n) ((unsigned char *)&netp)[n]
    if (netp != 0) {
        BUFFER_WRITE_CHECK(" and dst net %u.%u.%u.%u/%u", GET_BYTE(0), GET_BYTE(1), GET_BYTE(2), GET_BYTE(3),
                           mask_size);
    }
#undef GET_BYTE

    if (whitelist) {
        void *item;

        ARRAY_FOR_EACH(whitelist, item)
        {
            const hamoWhitelistEntry *entry = item;
            bool already_params = false;

#ifndef HAMO_IPV6_SUPPORTED
            if (entry->ipv6) {
                VASQ_WARNING(logger,
                             "Skipping whitelist entry because IPv6 addresses are not currently supported");
                continue;
            }
#endif

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
    }

    VASQ_DEBUG(logger, "BPF: %s", bpf);

    if (pcap_compile(handle, &program, bpf, true, 0) != 0) {
        VASQ_ERROR(logger, "pcap_compile: %s", pcap_geterr(handle));
        return HAMO_RET_PCAP_COMPILE;
    }

    ret = pcap_setfilter(handle, &program);
    pcap_freecode(&program);
    if (ret == 0) {
        ret = HAMO_RET_OK;
    }
    else {
        VASQ_ERROR(logger, "pcap_setfilter: %s", pcap_geterr(handle));
        ret = HAMO_RET_PCAP_SET_FILTER;
    }

    return ret;
}

#undef BUFFER_WRITE_CHECK

void
hamoDispatcherFree(hamoDispatcher *dispatcher)
{
    void *item;

    if (!dispatcher) {
        return;
    }

    ARRAY_FOR_EACH(&dispatcher->handles, item)
    {
        pcap_t *handle = *(pcap_t **)item;

        pcap_close(handle);
    }

    hamoArrayFree(&dispatcher->handles);
    hamoArrayFree(&dispatcher->journalers);
}

int
hamoPcapAdd(hamoArray *handles, const char *device, const hamoArray *whitelist)
{
    int ret, link_type;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *link_type_name;
    pcap_t *handle;

    if (!handles || !device) {
        VASQ_ERROR(logger, "handles and device cannot be NULL");
        return HAMO_RET_USAGE;
    }

    VASQ_INFO(logger, "Creating a packet capture handle for the %s device", device);

    handle = pcap_open_live(device, HAMO_MAX_BYTES_CAPTURED, true, 1000, errbuf);
    if (!handle) {
        VASQ_ERROR(logger, "pcap_open_live: %s", errbuf);
        return HAMO_RET_PCAP_OPEN;
    }

    link_type = pcap_datalink(handle);
    link_type_name = pcap_datalink_val_to_name(link_type);
    if (!hamoLinkTypeSupported(link_type)) {
        VASQ_ERROR(logger, "Unsupported data link type: %s", link_type_name);
        ret = HAMO_RET_PCAP_DATALINK_UNSUPPORTED;
        goto error;
    }
    VASQ_DEBUG(logger, "Data link type: %s", link_type_name);

    ret = setBpf(handle, device, whitelist);
    if (ret != HAMO_RET_OK) {
        goto error;
    }

    if (pcap_get_selectable_fd(handle) == PCAP_ERROR) {
        VASQ_ERROR(logger, "No selectable file descriptor associated with PCAP handle");
        ret = HAMO_RET_PCAP_NO_FD;
        goto error;
    }

    if (pcap_setnonblock(handle, true, errbuf) != 0) {
        VASQ_ERROR(logger, "pcap_setnonblock: %s", errbuf);
        ret = HAMO_RET_PCAP_SET_NONBLOCK;
        goto error;
    }

    ret = hamoArrayAppend(handles, &handle);
    if (ret != HAMO_RET_OK) {
        goto error;
    }

    return HAMO_RET_OK;

error:

    pcap_close(handle);
    return ret;
}

int
hamoPcapDispatch(const hamoDispatcher *dispatcher, int timeout)
{
    size_t idx;
    struct pollfd *pollers;
    void *item;

    if (!dispatcher) {
        VASQ_ERROR(logger, "dispatcher cannot be NULL");
        return HAMO_RET_USAGE;
    }

    if (dispatcher->handles.length == 0) {
        return HAMO_RET_OK;
    }

    pollers = alloca(sizeof(*pollers) * dispatcher->handles.length);
    idx = 0;
    ARRAY_FOR_EACH(&dispatcher->handles, item)
    {
        pcap_t *handle = *(pcap_t **)item;

        pollers[idx].fd = pcap_get_selectable_fd(handle);
        pollers[idx].events = POLLIN;
        idx++;
    }

    switch (poll(pollers, dispatcher->handles.length, timeout)) {
        int local_errno;

    case -1:
        local_errno = errno;
        if (local_errno == EINTR) {
            VASQ_WARNING(logger, "poll interrupted by a signal");
            return HAMO_RET_OK;
        }
        else {
            VASQ_PERROR(logger, "poll", local_errno);
            return HAMO_RET_POLL_FAILED;
        }

    case 0: break;

    default:
        for (size_t k = 0; k < dispatcher->handles.length; k++) {
            if (pollers[k].revents & POLLIN) {
                pcap_t *handle = *(pcap_t **)ARRAY_GET_ITEM(&dispatcher->handles, k);

                VASQ_DEBUG(logger, "Handle %zu is ready for reading", k);
                hamoProcessPacket(handle, &dispatcher->journalers);
            }
        }
        break;
    }

    return HAMO_RET_OK;
}
