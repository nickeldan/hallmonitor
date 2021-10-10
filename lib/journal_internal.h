#ifndef HALLMONITOR_JOURNAL_INTERNAL_H
#define HALLMONITOR_JOURNAL_INTERNAL_H

#include <hamo/definitions.h>
#include <hamo/journal.h>

/**
 * @brief Writes a packet capture record to the journal.
 *
 * @param record A pointer to the record.
 *
 * @return HAMO_RET_OK if successful and an error code otherwise.
 */
int HIDDEN_SYMBOL
hamoJournalWrite(const hamoRecord *record);

#endif  // HALLMONITOR_JOURNAL_INTERNAL_H