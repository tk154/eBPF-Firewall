#include "dsa.h"

#include <errno.h>
#include <stdio.h>

#include <net/if.h>

#include "../../log/log.h"


int dsa_get_tag_proto(__u32 ifindex, char *tag_proto) {
    int rc = BPFW_RC_OK;

    char ifname[IF_NAMESIZE];
    if_indextoname(ifindex, ifname);

    char tag_path[64];
    snprintf(tag_path, sizeof(tag_path), "/sys/class/net/%s/dsa/tagging", ifname);

    FILE *tag_file = fopen(tag_path, "r");
    if (!tag_file) {
        bpfw_error("Error opening '%s': %s (-%d).\n", tag_path, strerror(errno), errno);
        rc = BPFW_RC_ERROR;

        goto out;
    }

    if (!fgets(tag_proto, DSA_PROTO_MAX_LEN, tag_file)) {
        bpfw_error("Error reading '%s': %s (-%d).\n", tag_path, strerror(errno), errno);
        rc = BPFW_RC_ERROR;

        goto fclose;
    }

    tag_proto[strcspn(tag_proto, "\n")] = '\0';

fclose:
    fclose(tag_file);

out:
    return rc;
}
