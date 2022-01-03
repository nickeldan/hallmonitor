#include <stdio.h>
#include <stdlib.h>

#include <hamo/definitions.h>

vasqLogger *logger;

static void
loggerFree(void)
{
    vasqLoggerFree(logger);
}

int
hamoLoggerInit(int fd, vasqLogLevel_t level)
{
    int ret;

#ifdef DEBUG
#define LOGGER_FORMAT "%t [%L]%_ %f:%l: %M\n"
#else
#define LOGGER_FORMAT "%t [%L]%_ %M\n"
#endif

    ret = vasqLoggerCreate(fd, level, LOGGER_FORMAT, NULL, &logger);
    if (ret == VASQ_RET_OK) {
        atexit(loggerFree);
    }
    else {
        fprintf(stderr, "vasqLoggerCreate: %s\n", vasqErrorString(ret));
    }
    return ret;
}
