#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <hamo/whitelist.h>

static int
parseAddress(char **addr, const char *string, size_t length)
{
    int af;
    unsigned char buffer[16];

    *addr = VASQ_MALLOC(logger, length + 1);
    if (!*addr) {
        return HAMO_RET_OUT_OF_MEMORY;
    }
    memcpy(*addr, string, length);
    (*addr)[length] = '\0';

    af = strchr(*addr, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(af, *addr, buffer) != 1) {
        VASQ_ERROR(logger, "Invalid IP%s address: %s", (af == AF_INET) ? "" : "v6", *addr);
        free(*addr);
        *addr = NULL;
        return HAMO_RET_BAD_WHITELIST;
    }

    return HAMO_RET_OK;
}

static void
freeEntry(const hamoWhitelistEntry *entry)
{
    free(entry->saddr);
    free(entry->daddr);
}

int
hamoWhitelistLoad(FILE *file, hamoArray *entries)
{
    int ret;
    size_t orig_length;
    char line[256];

    if (!file || !entries) {
        VASQ_ERROR(logger, "The arguments cannot be NULL");
        return HAMO_RET_USAGE;
    }

    orig_length = entries->length;

    while (fgets(line, sizeof(line), file)) {
        hamoWhitelistEntry entry = {0};
        char *traverse = line, *comma;

        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        comma = strchr(traverse, ',');
        if (!comma) {
            VASQ_ERROR(logger, "Invalid whitelist entry:\n\n\t%s", line);
            ret = HAMO_RET_BAD_WHITELIST;
            goto error;
        }

        if (comma > traverse) {
            ret = parseAddress(&entry.saddr, traverse, comma - traverse);
            if (ret != HAMO_RET_OK) {
                goto error;
            }
            entry.ipv6 = !!strchr(entry.saddr, ':');
        }
        traverse = comma + 1;

        comma = strchr(traverse, ',');
        if (!comma) {
            VASQ_ERROR(logger, "Invalid whitelist entry:\n\n\t%s", line);
            ret = HAMO_RET_BAD_WHITELIST;
            freeEntry(&entry);
            goto error;
        }

        if (comma > traverse) {
            bool is_ipv6;

            ret = parseAddress(&entry.daddr, traverse, comma - traverse);
            if (ret != HAMO_RET_OK) {
                freeEntry(&entry);
                goto error;
            }
            is_ipv6 = !!strchr(entry.daddr, ':');

            if (entry.saddr) {
                if (entry.ipv6 != is_ipv6) {
                    VASQ_ERROR(logger, "Cannot pair an IPv4 address with an IPv6 address:\n\n\t%s", line);
                    ret = HAMO_RET_BAD_WHITELIST;
                    freeEntry(&entry);
                    goto error;
                }
            }
            else {
                entry.ipv6 = is_ipv6;
            }
        }
        traverse = comma + 1;

        if (*traverse != '\0') {
            long value;
            char *endptr;

            value = strtol(traverse, &endptr, 10);
            if (*endptr != '\0' || value <= 0 || value >= 65536) {
                VASQ_ERROR(logger, "Invalid port number: %s", traverse);
                ret = HAMO_RET_BAD_WHITELIST;
                freeEntry(&entry);
                goto error;
            }
            entry.dport = value;
        }

        ret = hamoArrayAppend(entries, &entry);
        if (ret != HAMO_RET_OK) {
            freeEntry(&entry);
            goto error;
        }
    }

    return HAMO_RET_OK;

error:
    for (size_t k = orig_length; k < entries->length; k++) {
        hamoWhitelistEntry *entry = ARRAY_GET_ITEM(entries, k);

        freeEntry(entry);
    }
    entries->length = orig_length;

    return ret;
}

void
hamoWhitelistFree(hamoArray *entries)
{
    void *item;

    ARRAY_FOR_EACH(entries, item)
    {
        freeEntry((hamoWhitelistEntry *)item);
    }

    hamoArrayFree(entries);
}
