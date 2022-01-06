#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <hamo/whitelist.h>

static int
parseAddress(char **addr, const char *string, size_t length)
{
    int af;
    unsigned char buffer[IPV6_SIZE];

    *addr = VASQ_MALLOC(hamo_logger, length + 1);
    if (!*addr) {
        return HAMO_RET_OUT_OF_MEMORY;
    }
    memcpy(*addr, string, length);
    (*addr)[length] = '\0';

    af = strchr(*addr, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(af, *addr, buffer) != 1) {
        VASQ_ERROR(hamo_logger, "Invalid IPv%s address: %s", (af == AF_INET) ? "4" : "6", *addr);
        free(*addr);
        *addr = NULL;
        return HAMO_RET_BAD_WHITELIST;
    }

    return HAMO_RET_OK;
}

void
hamoWhitelistEntryFree(hamoWhitelistEntry *entry)
{
    if (entry) {
        free(entry->saddr);
        free(entry->daddr);
        *entry = (hamoWhitelistEntry){0};
    }
}

int
hamoWhitelistEntryParse(const char *string, hamoWhitelistEntry *entry)
{
    int ret;
    const char *traverse = string, *comma;

    if (!string || !entry) {
        VASQ_ERROR(hamo_logger, "The arguments cannot be NULL");
        return HAMO_RET_USAGE;
    }

    *entry = (hamoWhitelistEntry){0};

    comma = strchr(traverse, ',');
    if (!comma) {
        VASQ_ERROR(hamo_logger, "Invalid whitelist entry: %s", string);
        return HAMO_RET_BAD_WHITELIST;
    }

    if (comma > traverse) {
        ret = parseAddress(&entry->saddr, traverse, comma - traverse);
        if (ret != HAMO_RET_OK) {
            return ret;
        }
        entry->ipv6 = !!strchr(entry->saddr, ':');
    }
    traverse = comma + 1;

    comma = strchr(traverse, ',');
    if (!comma) {
        VASQ_ERROR(hamo_logger, "Invalid whitelist entry: %s", string);
        ret = HAMO_RET_BAD_WHITELIST;
        goto error;
    }

    if (comma > traverse) {
        bool is_ipv6;

        ret = parseAddress(&entry->daddr, traverse, comma - traverse);
        if (ret != HAMO_RET_OK) {
            goto error;
        }
        is_ipv6 = !!strchr(entry->daddr, ':');

        if (entry->saddr) {
            if (entry->ipv6 != is_ipv6) {
                VASQ_ERROR(hamo_logger, "Cannot pair an IPv4 address with an IPv6 address: %s", string);
                ret = HAMO_RET_BAD_WHITELIST;
                goto error;
            }
        }
        else {
            entry->ipv6 = is_ipv6;
        }
    }
    traverse = comma + 1;

    if (*traverse != '\0') {
        long value;
        char *endptr;

        value = strtol(traverse, &endptr, 10);
        switch (*endptr) {
        case '\n':
        case '\r':
        case ' ':
        case '\t':
        case '\0':
            if (value > 0 && value < 65536) {
                break;
            }
            /* FALLTHROUGH */

        default:
            VASQ_ERROR(hamo_logger, "Invalid port number: %s", traverse);
            ret = HAMO_RET_BAD_WHITELIST;
            goto error;
        }
        entry->dport = value;
    }
    else if (!entry->saddr && !entry->daddr) {
        VASQ_ERROR(hamo_logger, "No whitelist information specified");
        ret = HAMO_RET_BAD_WHITELIST;
        goto error;
    }

    return HAMO_RET_OK;

error:
    hamoWhitelistEntryFree(entry);

    return ret;
}

int
hamoWhitelistLoad(FILE *file, hamoArray *entries)
{
    int ret;
    size_t orig_length;
    char line[256];

    if (!file || !entries) {
        VASQ_ERROR(hamo_logger, "The arguments cannot be NULL");
        return HAMO_RET_USAGE;
    }

    orig_length = entries->length;

    while (fgets(line, sizeof(line), file)) {
        hamoWhitelistEntry entry;

        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        ret = hamoWhitelistEntryParse(line, &entry);
        if (ret != HAMO_RET_OK) {
            goto error;
        }

        ret = hamoArrayAppend(entries, &entry);
        if (ret != HAMO_RET_OK) {
            hamoWhitelistEntryFree(&entry);
            goto error;
        }
    }

    return HAMO_RET_OK;

error:
    for (size_t k = orig_length; k < entries->length; k++) {
        hamoWhitelistEntry *entry = ARRAY_GET_ITEM(entries, k);

        hamoWhitelistEntryFree(entry);
    }
    entries->length = orig_length;

    return ret;
}

void
hamoWhitelistFree(hamoArray *entries)
{
    void *item;

    if (!entries) {
        return;
    }

    ARRAY_FOR_EACH(entries, item)
    {
        hamoWhitelistEntryFree((hamoWhitelistEntry *)item);
    }

    hamoArrayFree(entries);
}
