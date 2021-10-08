#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>

#include <hamo/capture.h>
#include <hamo/packet.h>
#include <hamo/whitelist.h>

#define HAMO_BPF_MAX_SIZE       1024
#define HAMO_MAX_BYTES_CAPTURED 512

static volatile sig_atomic_t sigint_caught;

#define BUFFER_WRITE_CHECK(format, ...)                                           \
    do {                                                                          \
        len += snprintf(bpf + len, sizeof(bpf) - len, format, ##__VA_ARGS__);     \
        if (len >= sizeof(bpf)) {                                                 \
            VASQ_ERROR(logger, "BPF is too long (%zu characters at least)", len); \
            ret = HAMO_RET_OVERFLOW;                                              \
            goto done;                                                            \
        }                                                                         \
    } while (0)

static int
setBpf(pcap_t *phandle, const char *device, const char *whitelist_file)
{
    int ret;
    size_t len, num_entries;
    bpf_u_int32 netp, maskp;
    char errbuf[PCAP_ERRBUF_SIZE], bpf[HAMO_BPF_MAX_SIZE] = "tcp[tcpflags] & (tcp-syn) != 0 and dst net ";
    hamoWhitelistEntry *entries = NULL;
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

#ifdef HAMO_IPV6_SUPPORTED
#error "IPv6 is not currently supported."
    BUFFER_WRITE_CHECK(" and (ip or ip6)");
#else
    BUFFER_WRITE_CHECK(" and ip");
#endif

    ret = hamoWhitelistLoad(whitelist_file, &entries, &num_entries);
    if (ret != HAMO_RET_OK) {
        return ret;
    }

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

    hamoWhitelistFree(entries);
    entries = NULL;

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

done:
    hamoWhitelistFree(entries);

    return ret;
}

#undef BUFFER_WRITE_CHECK

static void
sigintHandler(int signum)
{
    (void)signum;

    VASQ_DEBUG(logger, "SIGINT caught");

    sigint_caught = true;
}

int
hamoPcapCreate(hamoPcap *handle, const char *device, const char *whitelist_file)
{
    int ret, link_type;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!handle) {
        VASQ_ERROR(logger, "handle cannot be NULL");
        return HAMO_RET_USAGE;
    }

    *handle = (hamoPcap){0};

    handle->phandle = pcap_open_live(device, HAMO_MAX_BYTES_CAPTURED, true, 1000, errbuf);
    if (!handle->phandle) {
        VASQ_ERROR(logger, "pcap_open_live: %s", errbuf);
        return HAMO_RET_PCAP_OPEN;
    }

    link_type = pcap_datalink(handle->phandle);
    if (!hamoLinkTypeSupported(link_type)) {
        VASQ_ERROR(logger, "Unsupported data link type: %s", pcap_datalink_val_to_name(link_type));
        ret = HAMO_RET_PCAP_DATALINK_UNSUPPORTED;
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
hamoPcapDispatch(hamoPcap *handle, int timeout, int *num_packets)
{
    int ret = HAMO_RET_OK;
    struct sigaction action = {.sa_handler = sigintHandler}, old_action;
    struct pollfd poller;

    if (num_packets) {
        *num_packets = 0;
    }

    if (!handle) {
        VASQ_ERROR(logger, "handle cannot be NULL");
        return HAMO_RET_USAGE;
    }

    if (!handle->phandle || handle->fd < 0) {
        VASQ_ERROR(logger, "handle is uninitialized");
        return HAMO_RET_USAGE;
    }

    sigfillset(&action.sa_mask);
    sigaction(SIGINT, &action, &old_action);
    VASQ_DEBUG(logger, "SIGINT handler set");

    poller.fd = handle->fd;
    poller.events = POLLIN;

    VASQ_INFO(logger, "Beginning packet capture loop");

    while (!sigint_caught) {
        if (poll(&poller, 1, timeout) == -1) {
            int local_errno = errno;

            if (local_errno == EINTR) {
                VASQ_DEBUG(logger, "poll interrupted by a signal");
                continue;
            }
            else {
                VASQ_PERROR(logger, "poll", local_errno);
                ret = HAMO_RET_POLL_FAILED;
                goto done;
            }
        }

        if (poller.revents & POLLIN) {
            switch ((ret = hamoProcessPacket(handle->phandle))) {
            case HAMO_RET_OK:
                if (num_packets) {
                    (*num_packets)++;
                }
                break;

            case HAMO_RET_BAD_PACKET: break;

            case HAMO_RET_NO_PACKETS_AVAILABLE: ret = HAMO_RET_OK;
            /* FALLTHROUGH */
            default: goto done;
            }
        }
        else {
            break;
        }
    }

done:

    sigaction(SIGINT, &old_action, NULL);
    VASQ_DEBUG(logger, "SIGINT handler restored");

    VASQ_INFO(logger, "Exiting packet capture loop");

    return ret;
}

void
hamoPcapClose(hamoPcap *handle)
{
    if (handle) {
        pcap_close(handle->phandle);
        *handle = HAMO_PCAP_INIT;
    }
}