#ifdef __linux__

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <pthread.h>
#include <semaphore.h>

#include <hamo/definitions.h>
#include <reap/reap.h>

#include "proc_search.h"

struct threadArgs {
    const hamoRecord *record;
    sem_t sem;
};

static bool
ipv4RecordMatches(const hamoRecord *record, uint32_t addr_1, unsigned int port_1, uint32_t addr_2,
                  unsigned int port_2)
{
    return record->sport == port_1 && record->dport == port_2 &&
           memcmp(record->source_address, &addr_1, IPV4_SIZE) == 0 &&
           memcmp(record->destination_address, &addr_2, IPV4_SIZE) == 0;
}

static bool
findInodeOfSocket(const hamoRecord *record, ino_t *inode)
{
    bool ret = false;
    char line[256];
    FILE *f;

#ifdef HAMO_IPV6_SUPPORTED
#error "IPv6 is not currently supported."
#endif

    f = fopen("/proc/net/tcp", "r");
    if (!f) {
        VASQ_ERROR(hamo_logger, "Failed to open /proc/net/tcp: %s", strerror(errno));
        return false;
    }

    if (!fgets(line, sizeof(line), f)) {
        VASQ_ERROR(hamo_logger, "Failed to read from /proc/net/tcp");
        goto done;
    }

    while (fgets(line, sizeof(line), f)) {
        unsigned int local_addr, remote_addr, local_port, remote_port;
        unsigned long inode_long;

        if (sscanf(line, " %*u: %x:%x %x:%x %*s %*s %*s %*s %*u %*u %lu ", &local_addr, &local_port,
                   &remote_addr, &remote_port, &inode_long) != 5) {
            unsigned int len;

            len = strnlen(line, sizeof(line));
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }

            VASQ_ERROR(hamo_logger, "Malformed line in /proc/net/tcp: %s", line);
            goto done;
        }

        if (ipv4RecordMatches(record, local_addr, local_port, remote_addr, remote_port) ||
            ipv4RecordMatches(record, remote_addr, remote_port, local_addr, local_port)) {
            VASQ_DEBUG(hamo_logger, "Record matches socket at inode %lu", inode_long);
            *inode = inode_long;
            ret = true;
            goto done;
        }
    }

    VASQ_DEBUG(hamo_logger, "No entry in /proc/net/tcp matches record");

done:
    fclose(f);
    return ret;
}

static void *
threadFunc(void *args)
{
    int ret;
    ino_t inode;
    char expectation[20];
    struct threadArgs *args_struct = args;
    hamoRecord record;
    reapProcIterator iterator;
    reapProcInfo info;

    memcpy(&record, args_struct->record, sizeof(record));
    sem_post(&args_struct->sem);

    if (!findInodeOfSocket(&record, &inode)) {
        hamoRecord record_copy;

        VASQ_DEBUG(hamo_logger, "Zeroing out source fields and searching again");

        memcpy(&record_copy, &record, sizeof(record));
        memset(&record_copy.source_address, 0, sizeof(record_copy.source_address));
        record.sport = 0;

        if (!findInodeOfSocket(&record_copy, &inode)) {
            return NULL;
        }
    }

    snprintf(expectation, sizeof(expectation), "socket:[%lu]", (unsigned long)inode);

    ret = reapProcIteratorInit(&iterator);
    if (ret != REAP_RET_OK) {
        VASQ_ERROR(hamo_logger, "reapProcIteratorInit: %s", reapGetError());
        return NULL;
    }

    while ((ret = reapProcIteratorNext(&iterator, &info)) == REAP_RET_OK) {
        bool found = false;
        reapFdIterator fd_iterator;
        reapFdResult result;

        if (reapFdIteratorInit(info.pid, &fd_iterator) != REAP_RET_OK) {
            continue;
        }

        while (reapFdIteratorNext(&fd_iterator, &result) == REAP_RET_OK) {
            if (result.inode == inode && strncmp(result.file, expectation, sizeof(expectation)) == 0) {
                int so_far;
                char src_addr_buffer[INET6_ADDRSTRLEN], dst_addr_buffer[INET6_ADDRSTRLEN], msg[256];

                inet_ntop(record.ipv6 ? AF_INET6 : AF_INET, record.source_address, src_addr_buffer,
                          sizeof(src_addr_buffer));
                inet_ntop(record.ipv6 ? AF_INET6 : AF_INET, record.destination_address, dst_addr_buffer,
                          sizeof(dst_addr_buffer));

                so_far = snprintf(msg, sizeof(msg), "SYN packet sent from ");
                if (record.ipv6) {
                    so_far += snprintf(msg + so_far, sizeof(msg) - so_far, "[%s]", src_addr_buffer);
                }
                else {
                    so_far += snprintf(msg + so_far, sizeof(msg) - so_far, "%s", src_addr_buffer);
                }

                so_far += snprintf(msg + so_far, sizeof(msg) - so_far, ":%u to ", record.sport);

                if (record.ipv6) {
                    so_far += snprintf(msg + so_far, sizeof(msg) - so_far, "[%s]", dst_addr_buffer);
                }
                else {
                    so_far += snprintf(msg + so_far, sizeof(msg) - so_far, "%s", dst_addr_buffer);
                }

                snprintf(msg + so_far, sizeof(msg) - so_far, ":%u matched to PID %li (%s)", record.dport,
                         (long)info.pid, info.exe);

                VASQ_INFO(hamo_logger, "%s", msg);
                found = true;
                break;
            }
        }

        reapFdIteratorClose(&fd_iterator);

        if (found) {
            goto done;
        }
    }

    if (ret != REAP_RET_DONE) {
        VASQ_ERROR(hamo_logger, "reapProcIteratorNext: %s", reapGetError());
    }

done:
    reapProcIteratorClose(&iterator);

    return NULL;
}

void
startProcSearch(void *user, const hamoRecord *record)
{
    int ret;
    pthread_t thread;
    pthread_attr_t attr;
    struct threadArgs args_struct = {.record = record};

    (void)user;

    if (record->ack_flag) {
        return;
    }

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        VASQ_ERROR(hamo_logger, "pthread_attr_init: %s", strerror(ret));
        return;
    }

    sem_init(&args_struct.sem, 0, 0);

    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&thread, &attr, threadFunc, &args_struct);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        VASQ_ERROR(hamo_logger, "pthread_create: %s", strerror(ret));
        return;
    }

    sem_wait(&args_struct.sem);
}

#endif  // __linux__
