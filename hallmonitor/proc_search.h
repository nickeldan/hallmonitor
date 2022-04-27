#ifndef HALLMONITOR_PROC_SEARCH_H
#define HALLMONITOR_PROC_SEARCH_H

#ifdef __linux__

#include <hamo/journal.h>

void
startProcSearch(void *user, const hamoRecord *record);

#endif

#endif  // HALLMONITOR_PROC_SEARCH_H
