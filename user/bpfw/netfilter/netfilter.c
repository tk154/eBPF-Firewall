#include "netfilter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common_user.h"


#define NETFILTER_SYSFS_BASE_PATH "/proc/sys/net/netfilter/nf_"

int netfilter_sysfs_read(const char *filename, unsigned int *value) {
    char path[128];
    snprintf(path, sizeof(path), NETFILTER_SYSFS_BASE_PATH"%s", filename);

    FILE *file = fopen(path, "r");
    if (!file) {
        FW_ERROR("Error opening %s: %s (-%d).\n", path, strerror(errno), errno);
        return errno;
    }

    char buffer[16];
    if (!fgets(buffer, sizeof(buffer), file)) {
        FW_ERROR("Error reading %s value: %s (-%d).\n", filename, strerror(errno), errno);
        fclose(file);

        return errno;
    }

    fclose(file);

    char *endptr = NULL;
    *value = strtoul(buffer, &endptr, 10);
    if (buffer == endptr) {
        FW_ERROR("Error converting %s from %s to unsigned integer.\n", buffer, filename);
        return -1;
    }

    return 0;
}

int netfilter_sysfs_write(const char *filename, unsigned int value) {
    char path[128];
    snprintf(path, sizeof(path), NETFILTER_SYSFS_BASE_PATH"%s", filename);

    FILE *file = fopen(path, "w");
    if (!file) {
        FW_ERROR("Error opening %s: %s (-%d).\n", path, strerror(errno), errno);
        return errno;
    }

    if (fprintf(file, "%u", value) < 0) {
        FW_ERROR("Error writing %u to %s: %s (-%d).\n", value, filename, strerror(errno), errno);
        fclose(file);

        return errno;
    }

    fclose(file);

    return 0;
}
