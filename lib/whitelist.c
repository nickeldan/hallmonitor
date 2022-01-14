#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include <hamo/whitelist.h>

static int
parseAddress(char *addr, const char *string, size_t length)
{
    int af;
    unsigned char buffer[IPV6_SIZE];

    if (length >= INET6_ADDRSTRLEN) {
        VASQ_ERROR(hamo_logger, "String is too long to be an IP address");
        return HAMO_RET_BAD_WHITELIST;
    }

    memcpy(addr, string, length);
    addr[length] = '\0';

    af = strchr(addr, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(af, addr, buffer) != 1) {
        VASQ_ERROR(hamo_logger, "Invalid IPv%s address: %s", (af == AF_INET) ? "4" : "6", *addr);
        return HAMO_RET_BAD_WHITELIST;
    }

    return HAMO_RET_OK;
}

static int
entryParse(const char *string, hamoWhitelistEntry *entry)
{
    int ret;
    const char *traverse = string, *comma;

    *entry = (hamoWhitelistEntry){0};

    comma = strchr(traverse, ',');
    if (!comma) {
        VASQ_ERROR(hamo_logger, "Invalid whitelist entry: %s", string);
        return HAMO_RET_BAD_WHITELIST;
    }

    if (comma > traverse) {
        ret = parseAddress(entry->saddr, traverse, comma - traverse);
        if (ret != HAMO_RET_OK) {
            return ret;
        }
    }
    traverse = comma + 1;

    comma = strchr(traverse, ',');
    if (!comma) {
        VASQ_ERROR(hamo_logger, "Invalid whitelist entry: %s", string);
        return HAMO_RET_BAD_WHITELIST;
    }

    if (comma > traverse) {
        bool is_dest_ipv6;

        ret = parseAddress(entry->daddr, traverse, comma - traverse);
        if (ret != HAMO_RET_OK) {
            return ret;
        }
        is_dest_ipv6 = !!strchr(entry->daddr, ':');

        if (entry->saddr[0]) {
            bool is_source_ipv6;

            is_source_ipv6 = !!strchr(entry->saddr, ':');

            if (is_source_ipv6 != is_dest_ipv6) {
                VASQ_ERROR(hamo_logger, "Cannot pair an IPv4 address with an IPv6 address: %s", string);
                return HAMO_RET_BAD_WHITELIST;
            }
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

        default: VASQ_ERROR(hamo_logger, "Invalid port number: %s", traverse); return HAMO_RET_BAD_WHITELIST;
        }
        entry->port = value;
    }
    else if (!entry->saddr && !entry->daddr) {
        VASQ_ERROR(hamo_logger, "No whitelist information specified");
        return HAMO_RET_BAD_WHITELIST;
    }

    return HAMO_RET_OK;
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

        switch (line[0]) {
        case '\r':
        case '\n':
        case '\0':
        case '#': continue;

        default: break;
        }

        ret = entryParse(line, &entry);
        if (ret != HAMO_RET_OK) {
            goto error;
        }

        ret = hamoArrayAppend(entries, &entry);
        if (ret != HAMO_RET_OK) {
            goto error;
        }
    }

    return HAMO_RET_OK;

error:
    entries->length = orig_length;

    return ret;
}
