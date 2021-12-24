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
setBpf(pcap_t *phandle, const char *device, const hamoWhitelistEntry *entries, size_t num_entries)
{
    int ret;
    size_t len;
    bpf_u_int32 netp, maskp;
    unsigned int mask_size;
    char errbuf[PCAP_ERRBUF_SIZE], bpf[HAMO_BPF_MAX_SIZE] = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn";
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

    for (size_t k = 0; k < num_entries; k++) {
        bool already_params = false;

#ifndef HAMO_IPV6_SUPPORTED
        if (entries[k].ipv6) {
            VASQ_WARNING(logger,
                         "Skipping whitelist entry %zu because IPv6 addresses are not currently supported",
                         k);
            continue;
        }
#endif

        BUFFER_WRITE_CHECK(" and not (");

        if (entries[k].saddr) {
            BUFFER_WRITE_CHECK("src host %s", entries[k].saddr);
            already_params = true;
        }

        if (entries[k].dstaddr) {
            if (already_params) {
                BUFFER_WRITE_CHECK(" and ");
            }
            else {
                already_params = true;
            }

            BUFFER_WRITE_CHECK("dst host %s", entries[k].saddr);
        }

        if (entries[k].dport != 0) {
            if (already_params) {
                BUFFER_WRITE_CHECK(" and ");
            }

            BUFFER_WRITE_CHECK("dst port %u", entries[k].dport);
        }

        BUFFER_WRITE_CHECK(")");
    }

    VASQ_DEBUG(logger, "BPF: %s", bpf);

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
hamoPcapCreate(hamoPcap *handle, const char *device, const hamoWhitelistEntry *entries, size_t num_entries)
{
    int ret, link_type;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *link_type_name;

    if (!handle) {
        VASQ_ERROR(logger, "handle cannot be NULL");
        return HAMO_RET_USAGE;
    }

    if (!entries) {
        num_entries = 0;
    }

    VASQ_INFO(logger, "Creating a packet capture handle for the %s device", device);

    handle->phandle = pcap_open_live(device, HAMO_MAX_BYTES_CAPTURED, true, 1000, errbuf);
    if (!handle->phandle) {
        VASQ_ERROR(logger, "pcap_open_live: %s", errbuf);
        return HAMO_RET_PCAP_OPEN;
    }

    link_type = pcap_datalink(handle->phandle);
    link_type_name = pcap_datalink_val_to_name(link_type);
    if (!hamoLinkTypeSupported(link_type)) {
        VASQ_ERROR(logger, "Unsupported data link type: %s", link_type_name);
        ret = HAMO_RET_PCAP_DATALINK_UNSUPPORTED;
        goto error;
    }
    VASQ_DEBUG(logger, "Data link type: %s", link_type_name);

    ret = setBpf(handle->phandle, device, entries, num_entries);
    if (ret != HAMO_RET_OK) {
        goto error;
    }

    if (pcap_get_selectable_fd(handle->phandle) == PCAP_ERROR) {
        VASQ_ERROR(logger, "No selectable file descriptor associated with PCAP handle");
        ret = HAMO_RET_PCAP_NO_FD;
        goto error;
    }

    if (pcap_setnonblock(handle->phandle, true, errbuf) != 0) {
        VASQ_ERROR(logger, "pcap_setnonblock: %s", errbuf);
        ret = HAMO_RET_PCAP_SET_NONBLOCK;
        goto error;
    }

    return HAMO_RET_OK;

error:

    hamoPcapClose(handle);
    return ret;
}

int
hamoPcapDispatch(const hamoPcap *handles, size_t num_handles, int timeout)
{
    int ret = HAMO_RET_OK;
    struct pollfd *pollers;

    if (!handles) {
        VASQ_ERROR(logger, "handle cannot be NULL");
        return HAMO_RET_USAGE;
    }

    if (num_handles == 0) {
        return HAMO_RET_OK;
    }

    pollers = alloca(sizeof(*pollers) * num_handles);
    for (size_t k = 0; k < num_handles; k++) {
        if (handles[k].phandle) {
            pollers[k].fd = pcap_get_selectable_fd(handles[k].phandle);
            pollers[k].events = POLLIN;
        }
        else {
            pollers[k].fd = STDOUT_FILENO;  // A descriptor that will never be ready for reading.
            pollers[k].events = 0;
        }
    }

    switch (poll(pollers, num_handles, timeout)) {
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
        for (size_t k = 0; k < num_handles; k++) {
            if (pollers[k].revents & POLLIN) {
                VASQ_DEBUG(logger, "Handler %zu is ready for reading", k);
                hamoProcessPacket(handles[k].phandle);
            }
        }
        break;
    }

    return HAMO_RET_OK;
}

void
hamoPcapClose(hamoPcap *handle)
{
    if (handle) {
        pcap_close(handle->phandle);
        *handle = HAMO_PCAP_INIT;
    }
}
