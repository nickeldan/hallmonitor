#include <hamo/journal.h>

static int
nullJournaler(const hamoRecord *record, void *user);

static hamoJournaler active_journaler = nullJournaler;
static void *user_data;

static int
nullJournaler(const hamoRecord *record, void *user)
{
    (void)record;
    (void)user;
    return HAMO_RET_OK;
}

void
hamoJournalInit(hamoJournaler journaler, void *user)
{
    active_journaler = journaler ? journaler : nullJournaler;
    user_data = user;
}

int
hamoJournalWrite(const hamoRecord *record)
{
    if (!record) {
        VASQ_ERROR(logger, "record cannot be NULL");
        return HAMO_RET_USAGE;
    }

    return active_journaler(record, user_data);
}
