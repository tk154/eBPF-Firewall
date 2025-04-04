#include "pppoe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>

#include "../../log/log.h"

#define PPPOE_FILE_PATH "/proc/net/pppoe"
#define PPPOE_FILE_EOF  1


static void ipv6_to_mac(__u8 *ipv6, __u8 *mac) {
    mac[0] = ipv6[8] ^ (1 << 1);
    mac[1] = ipv6[9];  mac[2] = ipv6[10];
    mac[3] = ipv6[13]; mac[4] = ipv6[14]; mac[5] = ipv6[15];
}

static FILE *open_pppoe_file() {
    FILE *pppoe_file = fopen(PPPOE_FILE_PATH, "r");
    if (!pppoe_file) {
        bpfw_error("\nError opening '%s': %s (-%d).\n",
            PPPOE_FILE_PATH, strerror(errno), errno);

        return NULL;
    }

    char pppoe_line[64];
    if (!fgets(pppoe_line, sizeof(pppoe_line), pppoe_file)) {
        bpfw_error("\nError reading header from '%s': %s (-%d).\n",
            PPPOE_FILE_PATH, strerror(errno), errno);
            
        fclose(pppoe_file);

        return NULL;
    }

    return pppoe_file;
}

static int get_pppoe_line(FILE *pppoe_file, struct pppoe *pppoe) {
    char pppoe_line[64];
    if (!fgets(pppoe_line, sizeof(pppoe_line), pppoe_file)) {
        if (!feof(pppoe_file)) {
            bpfw_error("\nError reading '%s': %s (-%d).\n",
                PPPOE_FILE_PATH, strerror(errno), errno);

            return BPFW_RC_ERROR;
        }

        return PPPOE_FILE_EOF;
    }

    const char *delim = " ";
    char *pppoe_str = strtok(pppoe_line, delim);

    pppoe->id = strtoul(pppoe_str, NULL, 16);
    if (!pppoe->id) {
        bpfw_error("\nError parsing PPPoE session ID from '%s'.\n", pppoe_file);
        return BPFW_RC_ERROR;
    }

    pppoe_str = strtok(NULL, delim);

    if (sscanf(pppoe_str, "%02x:%02x:%02x:%02x:%02x:%02x",
        &pppoe->address[0], &pppoe->address[1], &pppoe->address[2],
        &pppoe->address[3], &pppoe->address[4], &pppoe->address[5]) != ETH_ALEN) {
            bpfw_error("\nError parsing destination MAC from '%s'.\n", pppoe_file);
            return BPFW_RC_ERROR;
        }

    pppoe_str = strtok(NULL, delim);
    pppoe_str[strcspn(pppoe_str, "\n")] = '\0';

    pppoe->device = if_nametoindex(pppoe_str);
    if (!pppoe->device) {
        bpfw_error("\nError parsing interface from '%s'.\n", pppoe_file);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int pppoe_get_device(void *peer_ip6, struct pppoe *pppoe) {
    __u8 mac[ETH_ALEN];
    FILE *pppoe_file;
    int rc;

    ipv6_to_mac(peer_ip6, mac);

    pppoe_file = open_pppoe_file();
    if (!pppoe_file)
        return BPFW_RC_ERROR;

    while ((rc = get_pppoe_line(pppoe_file, pppoe)) == BPFW_RC_OK) {
        if (memcmp(pppoe->address, mac, ETH_ALEN - 3) == 0)
            break;
    }

    if (rc == PPPOE_FILE_EOF)
        bpfw_verbose("\nCouldn't find peer address %02x:%02x:%02x:%02x:%02x:%02x inside '%s'.\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], PPPOE_FILE_PATH);

    return rc;
}
