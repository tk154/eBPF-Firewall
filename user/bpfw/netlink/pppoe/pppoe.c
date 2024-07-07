#include "pppoe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>

#include "../../logging/logging.h"


static void ipv6_to_mac(__u8 *ipv6, __u8 *mac) {
    mac[0] = ipv6[8] ^ (1 << 1);
    mac[1] = ipv6[9];  mac[2] = ipv6[10];
    mac[3] = ipv6[13]; mac[4] = ipv6[14]; mac[5] = ipv6[15];
}

int get_pppoe_device(struct pppoe_device *pppoe, __u8 *ipv6) {
    __u8 mac[ETH_ALEN];
    ipv6_to_mac(ipv6, mac);

    int rc = 0;
    const char *pppoe_file_path = "/proc/net/pppoe";

    FILE *pppoe_file = fopen(pppoe_file_path, "r");
    if (!pppoe_file) {
        bpfw_error("\nError opening '%s': %s (-%d).\n", pppoe_file_path, strerror(errno), errno);
        rc = -1;

        goto out;
    }

    char pppoe_line[64];
    fgets(pppoe_line, sizeof(pppoe_line), pppoe_file);

    while (fgets(pppoe_line, sizeof(pppoe_line), pppoe_file)) {
        const char *delim = " ";
        char *pppoe_str = strtok(pppoe_line, delim);

        __u32 pppoe_id = strtoul(pppoe_str, NULL, 16);
        if (!pppoe_id) {
            bpfw_error("\nError parsing PPPoE session ID from '%s'.\n", pppoe_file);
            rc = -1;

            goto close_file;
        }

        pppoe_str = strtok(NULL, delim);

        __u8 address[ETH_ALEN];
        if (sscanf(pppoe_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            &address[0], &address[1], &address[2],
            &address[3], &address[4], &address[5]) != ETH_ALEN) {
                bpfw_error("\nError parsing destination MAC from '%s'.\n", pppoe_file);
                rc = -1;

                goto close_file;
            }

        if (memcmp(mac, address, ETH_ALEN) != 0)
            continue;

        pppoe_str = strtok(NULL, delim);
        pppoe_str[strcspn(pppoe_str, "\n")] = '\0';

        __u32 pppoe_device = if_nametoindex(pppoe_str);
        if (!pppoe_device) {
            bpfw_error("\nError parsing interface from '%s'.\n", pppoe_file);
            rc = -1;

            goto close_file;
        }

        pppoe->id = pppoe_id;
        pppoe->device = pppoe_device;
        memcpy(pppoe->address, address, ETH_ALEN);

        goto close_file;
    }

    if (!feof(pppoe_file)) {
        bpfw_error("\nError reading '%s': %s (-%d).\n", pppoe_file_path, strerror(errno), errno);
        rc = -1;
    }
    else {
        bpfw_verbose("\nCouldn't find peer address %02x:%02x:%02x:%02x:%02x:%02x inside '%s'.\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pppoe_file_path);

        rc = 1;
    }

close_file:
    fclose(pppoe_file);

out:
    return rc;
}
