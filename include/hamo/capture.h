#ifndef HALLMONITOR_CAPTURE_H
#define HALLMONITOR_CAPTURE_H

#include <poll.h>

#include <pcap.h>

#include "array.h"
#include "definitions.h"
#include "journal.h"

typedef struct hamoDispatcher {
    hamoArray handles;
    hamoArray pollers;
    hamoArray journalers;
} hamoDispatcher;

#define HAMO_DISPATCHER_INIT                                                       \
    (hamoDispatcher)                                                               \
    {                                                                              \
        HAMO_ARRAY(pcap_t *), HAMO_ARRAY(struct pollfd), HAMO_ARRAY(hamoJournaler) \
    }

void
hamoDispatcherFree(hamoDispatcher *dispatcher);

/**
 * @brief Creates and activates a PCAP handle which is added to an array.
 *
 * @param dispatcher A pointer to the dispatcher.
 * @param device The name of the network device on which to capture.  If NULL, defaults to "any".
 * @param whitelist If not NULL, an array of whitelist entries to be incorporated into the BPF.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int
hamoPcapAdd(hamoDispatcher *dispatcher, const char *device, const hamoArray *whitelist);

/**
 * @brief Checks an array of packet capturing handles, processing at most one packet from each one.
 *
 * @param dispatcher A pointer to the dispatcher.
 * @param timeout The number of seconds to wait for packets to become available.  A negative value means an
 * infinite timeout.
 *
 * @return HAMO_RET_OK if sucessful and an error code otherwise.
 */
int
hamoPcapDispatch(const hamoDispatcher *dispatcher, int timeout);

#endif  // HALLMONITOR_CAPTURE_H
