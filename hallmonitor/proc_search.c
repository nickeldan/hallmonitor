#ifdef __linux__

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <semaphore.h>

#include <reap/reap.h>

#include <hamo/definitions.h>

#include "proc_search.h"

struct threadArgs {
    const hamoRecord *record;
    sem_t sem;
};

static bool
ipv4RecordMatches(const reapNetResult *result, const hamoRecord *record)
{
    if (result->remote.port == 0) {
        return false;
    }

    if (result->local.port == record->sport && result->remote.port == record->dport &&
        memcmp(result->local.address, record->source_address, IPV4_SIZE) == 0 &&
        memcmp(result->remote.address, record->destination_address, IPV4_SIZE) == 0) {
        return true;
    }

    return result->remote.port == record->sport && result->local.port == record->dport &&
           memcmp(result->remote.address, record->source_address, IPV4_SIZE) == 0 &&
           memcmp(result->local.address, record->destination_address, IPV4_SIZE) == 0;
}

static bool
ipv6RecordMatches(const reapNet6Result *result, const hamoRecord *record)
{
    if (result->remote.port == 0) {
        return false;
    }

    if (result->local.port == record->sport && result->remote.port == record->dport &&
        memcmp(&result->local.address, record->source_address, IPV6_SIZE) == 0 &&
        memcmp(&result->remote.address, record->destination_address, IPV6_SIZE) == 0) {
        return true;
    }

    return result->remote.port == record->dport && result->local.port == record->sport &&
           memcmp(&result->remote.address, record->source_address, IPV6_SIZE) == 0 &&
           memcmp(&result->local.address, record->destination_address, IPV6_SIZE) == 0;
}

static bool
findInodeOfSocket4(const hamoRecord *record, ino_t *inode)
{
    bool ret = false;
    int errnum;
    reapNetIterator iterator;
    reapNetResult result;

    if (reapNetIteratorInit(&iterator, true) != REAP_RET_OK) {
        VASQ_ERROR(hamo_logger, "reapNetIteratorInit: %s", reapGetError());
        return false;
    }

    while ((errnum = reapNetIteratorNext(&iterator, &result)) == REAP_RET_OK) {
        VASQ_DEBUG(hamo_logger, "Examining socket at inode %lu", (unsigned long)result.inode);
        if (ipv4RecordMatches(&result, record)) {
            *inode = result.inode;
            ret = true;
            VASQ_DEBUG(hamo_logger, "SYN packet matches socket at inode %lu", (unsigned long)result.inode);
            goto done;
        }
    }

    if (errnum != REAP_RET_DONE) {
        VASQ_ERROR(hamo_logger, "reapNetIteratorNext: %s", reapGetError());
    }

done:

    reapNetIteratorClose(&iterator);
    return ret;
}

static bool
findInodeOfSocket6(const hamoRecord *record, ino_t *inode)
{
    bool ret = false;
    int errnum;
    reapNet6Iterator iterator;
    reapNet6Result result;

    if (reapNet6IteratorInit(&iterator, true) != REAP_RET_OK) {
        VASQ_ERROR(hamo_logger, "reapNet6IteratorInit: %s", reapGetError());
        return false;
    }

    while ((errnum = reapNet6IteratorNext(&iterator, &result)) == REAP_RET_OK) {
        if (ipv6RecordMatches(&result, record)) {
            *inode = result.inode;
            ret = true;
            VASQ_DEBUG(hamo_logger, "SYN packet matches socket at inode %lu", (unsigned long)result.inode);
            goto done;
        }
    }

    if (errnum != REAP_RET_DONE) {
        VASQ_ERROR(hamo_logger, "reapNet6IteratorNext: %s", reapGetError());
    }

done:

    reapNet6IteratorClose(&iterator);
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

    if (!(record.ipv6 ? findInodeOfSocket6 : findInodeOfSocket4)(&record, &inode)) {
        VASQ_WARNING(hamo_logger, "No inode found matching SYN packet");
        return NULL;
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
