#ifndef HALLMONITOR_CAPTURE_H
#define HALLMONITOR_CAPTURE_H

#include <pcap.h>

#include "definitions.h"

typedef struct hamoPcap {
    pcap_t *phandle;
    int fd;
} hamoPcap;

#define HAMO_PCAP_INIT            \
    (hamoPcap)                    \
    {                             \
        .phandle = NULL, .fd = -1 \
    }

/**
 * @brief Creates and activates a PCAP handle.
 *
 * @param handle A pointer to the structure to be populated.
 * @param device The name of the network device on which to capture.  If NULL, defaults to "any".
 * @param whitelist_file If not NULL, specifies a file containing whitelist information to include in the
 * BPF.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoPcapCreate(hamoPcap *handle, const char *device, const char *whitelist_file);

/**
 * @brief Loops, processing packets.  This function can be interrupted by sending the process a SIGINT.
 *
 * @param handle A pointer to the hamoPcap.
 * @param timeout The number of seconds to wait for packets to become available.  A negative value means an
 * infinite timeout.
 * @param num_packets If not NULL, then its referenced integer will be set to the number of packets
 * successfully processed.
 *
 * @return HAMO_RET_OK if sucessful and an error code otherwise.
 */
int
hamoPcapDispatch(hamoPcap *handle, int timeout, int *num_packets);

/**
 * @brief Frees any resources associated with a hamoPcap.
 *
 * @param handle A pointer to the hamoPcap.
 */
void
hamoPcapClose(hamoPcap *handle);

#endif  // HALLMONITOR_CAPTURE_H
