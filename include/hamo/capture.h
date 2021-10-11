#ifndef HALLMONITOR_CAPTURE_H
#define HALLMONITOR_CAPTURE_H

#include <pcap.h>

#include "definitions.h"
#include "whitelist.h"

typedef struct hamoPcap {
    pcap_t *phandle;
} hamoPcap;

#define HAMO_PCAP_INIT  \
    (hamoPcap)          \
    {                   \
        .phandle = NULL \
    }

/**
 * @brief Creates and activates a PCAP handle.
 *
 * @param handle A pointer to the structure to be populated.
 * @param device The name of the network device on which to capture.  If NULL, defaults to "any".
 * @param entries If not NULL, a pointer to an array of whitelist entries used to form the BPF.
 * @param num_entries The number of whitelist entries.
 * BPF.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoPcapCreate(hamoPcap *handle, const char *device, const hamoWhitelistEntry *entries, size_t num_entries);

/**
 * @brief Checks an array of packet capturing handles, processing at most one packet from each one.
 *
 * @param handles An array of handles.
 * @param num_handles The length of the array.
 * @param timeout The number of seconds to wait for packets to become available.  A negative value means an
 * infinite timeout.
 *
 * @return HAMO_RET_OK if sucessful and an error code otherwise.
 */
int
hamoPcapDispatch(const hamoPcap *handles, size_t num_handles, int timeout);

/**
 * @brief Frees any resources associated with a hamoPcap.
 *
 * @param handle A pointer to the hamoPcap.
 */
void
hamoPcapClose(hamoPcap *handle);

#endif  // HALLMONITOR_CAPTURE_H
