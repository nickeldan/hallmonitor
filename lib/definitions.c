#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hamo/definitions.h>

vasqLogger *logger;

static void
loggerFree(void)
{
    vasqLoggerFree(logger);
}

int
hamoLoggerInit(vasqLogLevel_t level)
{
    int ret;

    ret = vasqLoggerCreate(STDOUT_FILENO, level, "%t [%L]%_ %f:%l: %M\n", NULL, &logger);
    if (ret != VASQ_RET_OK) {
        fprintf(stderr, "vasqLoggerCreate: %s\n", vasqErrorString(ret));
        return ret;
    }

    atexit(loggerFree);

    return VASQ_RET_OK;
}
