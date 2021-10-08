#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "definitions.h"

vasqLogger *logger;

static void
loggerFree(void)
{
    vasqLoggerFree(logger);
}

int
hamoLoggerInit(void)
{
    int ret;

    ret = vasqLoggerCreate(STDOUT_FILENO, LL_USE, "%t [%L]%_ %f:%l: %M\n", NULL, &logger);
    if (ret != VASQ_RET_OK) {
        fprintf(stderr, "vasqLoggerCreate: %s\n", vasqErrorString(ret));
        return ret;
    }

    atexit(loggerFree);

    return VASQ_RET_OK;
}
