#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#include <hamo/journal.h>

static hamoJournaler active_journaler = HAMO_NULL_JOURNALER;
static void *user_data;

static void
printRecord(const hamoRecord *record)
{
    int af = record->ipv6 ? AF_INET6 : AF_INET;
    time_t timestamp = record->timestamp;
    char time_buffer[26], src_buffer[INET6_ADDRSTRLEN], dst_buffer[INET6_ADDRSTRLEN];

    ctime_r(&timestamp, time_buffer);
    inet_ntop(af, &record->source_address, src_buffer, sizeof(src_buffer));
    inet_ntop(af, &record->destination_address, dst_buffer, sizeof(src_buffer));

    if (record->ipv6) {
        VASQ_INFO(logger, "At %s, a SYN packet was sent from [%s]:%u to [%s]:%u", time_buffer, src_buffer,
                  record->sport, dst_buffer, record->dport);
    }
    else {
        VASQ_INFO(logger, "At %s, a SYN packet was sent from %s:%u to %s:%u", time_buffer, src_buffer,
                  record->sport, dst_buffer, record->dport);
    }
}

void
hamoJournalInit(hamoJournaler journaler, void *user)
{
    active_journaler = journaler;
    user_data = user;
}

int
hamoJournalWrite(const hamoRecord *record)
{
    if (!record) {
        VASQ_ERROR(logger, "record cannot be NULL");
        return HAMO_RET_USAGE;
    }

    printRecord(record);

    if (active_journaler == HAMO_NULL_JOURNALER) {
        return HAMO_RET_OK;
    }
    else {
        return active_journaler(record, user_data);
    }
}