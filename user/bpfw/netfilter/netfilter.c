#include "netfilter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common_user.h"


int read_netfilter_sysfs_timeout(const char *filename, unsigned int *timeout) {
    const char* base_path = "/proc/sys/net/netfilter/%s";

    char path[128];
    snprintf(path, sizeof(path), base_path, filename);

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
    *timeout = strtoul(buffer, &endptr, 10);
    if (buffer == endptr) {
        FW_ERROR("Error converting %s value to unsigned integer.\n", filename);
        return -1;
    }

    return 0;
}
