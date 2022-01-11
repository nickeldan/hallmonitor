#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hamo/capture.h>
#include <hamo/whitelist.h>

#include "packet_internal.h"

#define HAMO_BPF_MAX_SIZE       1024
#define HAMO_MAX_BYTES_CAPTURED 512

#define BUFFER_WRITE_CHECK(format, ...)                                                \
    do {                                                                               \
        len += snprintf(bpf + len, sizeof(bpf) - len, format, ##__VA_ARGS__);          \
        if (len >= sizeof(bpf)) {                                                      \
            VASQ_ERROR(hamo_logger, "BPF is too long (%zu characters at least)", len); \
            return HAMO_RET_OVERFLOW;                                                  \
        }                                                                              \
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
        VASQ_CRITICAL(hamo_logger, "BPF buffer is too small");
        return HAMO_RET_OVERFLOW;
    }

#ifdef HAMO_IPV6_SUPPORTED
#error "IPv6 is not currently supported."
#endif

    if (pcap_lookupnet(device, &netp, &maskp, errbuf) != 0) {
        VASQ_ERROR(hamo_logger, "pcap_lookupnet: %s", errbuf);
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
        const char *types[2] = {"src", "dst"};
        for (int k = 0; k < 2; k++) {
            BUFFER_WRITE_CHECK(" and %s net %u.%u.%u.%u/%u", types[k], GET_BYTE(0), GET_BYTE(1), GET_BYTE(2),
                               GET_BYTE(3), mask_size);
        }
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
                VASQ_WARNING(hamo_logger,
                             "Skipping whitelist entry because IPv6 addresses are not currently supported");
                continue;
            }
#endif

            BUFFER_WRITE_CHECK(" and not (");

            if (entry->saddr) {
                BUFFER_WRITE_CHECK("src host %s", entry->saddr);
                already_params = true;
            }

            if (entry->daddr) {
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

                BUFFER_WRITE_CHECK("port %u", entry->dport);
            }

            BUFFER_WRITE_CHECK(")");
        }
    }

    VASQ_DEBUG(hamo_logger, "BPF: %s", bpf);

    if (pcap_compile(handle, &program, bpf, true, 0) != 0) {
        VASQ_ERROR(hamo_logger, "pcap_compile: %s", pcap_geterr(handle));
        return HAMO_RET_PCAP_COMPILE;
    }

    ret = pcap_setfilter(handle, &program);
    pcap_freecode(&program);
    if (ret == 0) {
        ret = HAMO_RET_OK;
    }
    else {
        VASQ_ERROR(hamo_logger, "pcap_setfilter: %s", pcap_geterr(handle));
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
        pcap_close(*(pcap_t **)item);
    }

    hamoArrayFree(&dispatcher->handles);
    hamoArrayFree(&dispatcher->pollers);
    hamoArrayFree(&dispatcher->journalers);
}

int
hamoPcapAdd(hamoDispatcher *dispatcher, const char *device, const hamoArray *whitelist)
{
    int ret, link_type;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *link_type_name;
    pcap_t *handle;
    struct pollfd poller;

    if (!dispatcher || !device) {
        VASQ_ERROR(hamo_logger, "dispatcher and device cannot be NULL");
        return HAMO_RET_USAGE;
    }

    VASQ_INFO(hamo_logger, "Creating a packet capture handle for the \"%s\" device", device);

    handle = pcap_open_live(device, HAMO_MAX_BYTES_CAPTURED, true, 1000, errbuf);
    if (!handle) {
        VASQ_ERROR(hamo_logger, "pcap_open_live: %s", errbuf);
        return HAMO_RET_PCAP_OPEN;
    }

    link_type = pcap_datalink(handle);
    link_type_name = pcap_datalink_val_to_name(link_type);
    if (!hamoLinkTypeSupported(link_type)) {
        VASQ_ERROR(hamo_logger, "Unsupported data link type: %s", link_type_name);
        ret = HAMO_RET_PCAP_DATALINK_UNSUPPORTED;
        goto error;
    }
    VASQ_DEBUG(hamo_logger, "Data link type: %s", link_type_name);

    ret = setBpf(handle, device, whitelist);
    if (ret != HAMO_RET_OK) {
        goto error;
    }

    poller.fd = pcap_get_selectable_fd(handle);
    if (poller.fd == PCAP_ERROR) {
        VASQ_ERROR(hamo_logger, "No selectable file descriptor associated with PCAP handle");
        ret = HAMO_RET_PCAP_NO_FD;
        goto error;
    }
    poller.events = POLLIN;

    if (pcap_setnonblock(handle, true, errbuf) != 0) {
        VASQ_ERROR(hamo_logger, "pcap_setnonblock: %s", errbuf);
        ret = HAMO_RET_PCAP_SET_NONBLOCK;
        goto error;
    }

    ret = hamoArrayAppend(&dispatcher->handles, &handle);
    if (ret != HAMO_RET_OK) {
        goto error;
    }

    ret = hamoArrayAppend(&dispatcher->pollers, &poller);
    if (ret != HAMO_RET_OK) {
        dispatcher->handles.length--;
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
    int ret = HAMO_RET_OK;
    struct pollfd *pollers;

    if (!dispatcher) {
        VASQ_ERROR(hamo_logger, "dispatcher cannot be NULL");
        return HAMO_RET_USAGE;
    }

    if (dispatcher->handles.length == 0) {
        return HAMO_RET_OK;
    }

    VASQ_ASSERT(hamo_logger, dispatcher->handles.length == dispatcher->pollers.length);

    pollers = ARRAY_GET_ITEM(&dispatcher->pollers, 0);

    switch (poll(pollers, dispatcher->pollers.length, timeout)) {
        int local_errno;

    case -1:
        local_errno = errno;
        if (local_errno == EINTR) {
            VASQ_WARNING(hamo_logger, "poll interrupted by a signal");
        }
        else {
            VASQ_PERROR(hamo_logger, "poll", local_errno);
            ret = HAMO_RET_POLL_FAILED;
        }
        break;

    case 0: break;

    default:
        for (size_t k = 0; k < dispatcher->handles.length; k++) {
            if (pollers[k].revents & POLLIN) {
                pcap_t *handle = *(pcap_t **)ARRAY_GET_ITEM(&dispatcher->handles, k);

                VASQ_DEBUG(hamo_logger, "Handle %zu is ready for reading", k);
                hamoProcessPacket(handle, &dispatcher->journalers);
            }
        }
        break;
    }

    return ret;
}
