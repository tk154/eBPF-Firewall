#include "conntrack.h"

#include "nat.h"
#include "ip_attr.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <linux/netfilter/nf_conntrack_tcp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "../logging/logging.h"


struct conntrack_handle {
    // Store the nf_conntrack handle pointer
    struct nfct_handle *ct_handle;

    // Timeouts from /proc/sys/net/netfilter
    // Note: There are more, for now just basic ones
    __u32 tcp_timeout, udp_timeout, udp_stream_timeout;
};

struct nfct_get_cb_args {
    struct conntrack_handle *conntrack_h;
    struct flow_key_value *flow;

    enum conntrack_conn_state state;
};


#define CONNTRACK_SYSFS_BASE_PATH "/proc/sys/net/netfilter/nf_conntrack_"

static FILE *open_conntrack_sysfs_file(const char *filename, const char *mode) {
    char path[128];
    snprintf(path, sizeof(path), CONNTRACK_SYSFS_BASE_PATH"%s", filename);

    FILE *file = fopen(path, mode);
    if (!file)
        bpfw_error("Error opening %s: %s (-%d).\n", path, strerror(errno), errno);

    return file;
}

/**
 * Reads timeout values from /proc/sys/net/netfilter/nf_conntrack_<filename>
 * @param filename The timeout value to read
 * @param timeout Where to store the timeout value
 * @returns 0 on success, errno otherwise
 * **/
static int read_conntrack_sysfs_value(const char *filename, unsigned int *value) {
    FILE *file = open_conntrack_sysfs_file(filename, "r");
    if (!file)
        return BPFW_RC_ERROR;

    int rc = BPFW_RC_OK;
    char buffer[16];

    if (!fgets(buffer, sizeof(buffer), file)) {
        bpfw_error("Error reading %s value: %s (-%d).\n", filename, strerror(errno), errno);
        rc = BPFW_RC_ERROR;

        goto fclose;
    }

    char *endptr = NULL;
    *value = strtoul(buffer, &endptr, 10);

    if (buffer == endptr) {
        bpfw_error("Error converting %s from %s to unsigned integer.\n", buffer, filename);
        rc = BPFW_RC_ERROR;
    }

fclose:
    fclose(file);

    return rc;
}

static int write_conntrack_sysfs_value(const char *filename, unsigned int value) {
    FILE *file = open_conntrack_sysfs_file(filename, "w");
    if (!file)
        return BPFW_RC_ERROR;

    int rc = BPFW_RC_OK;

    if (fprintf(file, "%u", value) < 0) {
        bpfw_error("Error writing %u to %s: %s (-%d).\n", value, filename, strerror(errno), errno);
        rc = BPFW_RC_ERROR;
    }

    fclose(file);

    return rc;
}

/**
 * Updates/Refreshes the nf_conntrack timeout
 * @param ct The nf_conntrack entry where to update the timeout
 * @param l4_proto The L4 protocol type (TCP or UDP)
 * **/
static int set_timeout(struct conntrack_handle* conntrack_h, struct nf_conntrack *ct, __u8 proto) {
    bool assured = nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_ASSURED;
    __u32 timeout = proto == IPPROTO_TCP ? conntrack_h->tcp_timeout :
        assured ? conntrack_h->udp_stream_timeout : conntrack_h->udp_timeout;

    // Set the new timeout
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);

    // Update the edited nf_conntrack entry
    if (nfct_query(conntrack_h->ct_handle, NFCT_Q_UPDATE, ct) != 0) {
        bpfw_error("Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

static bool tcp_not_established(__u8 proto, struct nf_conntrack *ct) {
    return proto == IPPROTO_TCP &&
        nfct_get_attr_u8(ct, ATTR_TCP_STATE) != TCP_CONNTRACK_ESTABLISHED;
}


// Callback to retrieve a specific conntrack entry
static int nfct_get_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct nfct_get_cb_args *args = data;
    struct conntrack_handle *conntrack_h = args->conntrack_h;
    struct flow_key_value *flow = args->flow;
    enum conntrack_conn_state *state = &args->state;

    if (tcp_not_established(flow->key.proto, ct)) {
        // If the flow isn't established yet or anymore,
        // the BPF program shouldn't forward its packages
        *state = CONNECTION_NOT_ESTABLISHED;
        return NFCT_CB_CONTINUE;
    }

    // Mark the flow as established so that the BPF program can take over now
    *state = CONNECTION_ESTABLISHED;

    switch (flow->value.action) {
        case ACTION_NONE:
            bpfw_debug_key("\nCon: ", &flow->key);

            memset(&flow->value.next, 0, sizeof(flow->value.next));
            
            // Since the TTL is decremented, we must increment the checksum for IPv4
            if (flow->key.family == AF_INET)
                flow->value.next.ipv4_cksum_diff = htons(0x0100);

            // Check for NAT
            check_nat(ct, flow);
        break;

        case ACTION_REDIRECT:
            // If there was no new package
            if (flow->value.idle > 0)
                break;

            // Update the nf_conntrack timeout
            if (set_timeout(conntrack_h, ct, flow->key.proto) != 0)
                return NFCT_CB_FAILURE;
        break;
    }

    return NFCT_CB_CONTINUE;
}


struct conntrack_handle* conntrack_init() {
    struct conntrack_handle *conntrack_h = (struct conntrack_handle*)malloc(sizeof(struct conntrack_handle));
    if (!conntrack_h) {
        bpfw_error("Error allocating conntrack handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    // Read TCP and UDP timeout values
    if (read_conntrack_sysfs_value ("tcp_timeout_established", &conntrack_h->tcp_timeout) != 0 ||
        read_conntrack_sysfs_value ("udp_timeout"            , &conntrack_h->udp_timeout) != 0 ||
        read_conntrack_sysfs_value ("udp_timeout_stream"     , &conntrack_h->udp_stream_timeout) != 0 ||
        write_conntrack_sysfs_value("acct", 0) != 0 ||
        write_conntrack_sysfs_value("tcp_be_liberal", 1) != 0)
    {
        bpfw_error("Is the nf_conntrack module loaded? (modprobe nf_conntrack)\n");
        goto free;
    }

    // Open a new conntrack handle
	conntrack_h->ct_handle = nfct_open(CONNTRACK, 0);
	if (!conntrack_h->ct_handle) {
		bpfw_error("Error opening conntrack handle: %s (-%d).\n", strerror(errno), errno);
		goto free;
	}

    return conntrack_h;

free:
    free(conntrack_h);

    return NULL;
}


int conntrack_lookup(struct conntrack_handle* conntrack_h, struct flow_key_value *flow) {
    // Create a new conntrack entry object for a lookup
    struct nf_conntrack *ct = nfct_new();
    if (!ct) {
        bpfw_error("Error allocating conntrack object: %s (-%d).\n",
            strerror(errno), errno);

        return BPFW_RC_ERROR;
    }

    // Set the attributes accordingly
    nfct_set_attr_u8 (ct, ATTR_L3PROTO,  flow->key.family);
    nfct_set_attr_u8 (ct, ATTR_L4PROTO,  flow->key.proto);
    nfct_set_attr_ip (ct, ATTR_IP_SRC,   flow->key.src_ip, flow->key.family);
    nfct_set_attr_ip (ct, ATTR_IP_DST,   flow->key.dest_ip, flow->key.family);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, flow->key.src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, flow->key.dest_port);

    int rc;
    struct nfct_get_cb_args args = { .conntrack_h = conntrack_h, .flow = flow };

    // Register the callback for retrieving single conntrack entries
    if (nfct_callback_register(conntrack_h->ct_handle, NFCT_T_ALL, nfct_get_cb, &args) != 0) {
        bpfw_error("Error registering conntrack callback: %s (-%d).\n", strerror(errno), errno);
        rc = BPFW_RC_ERROR;

        goto nfct_destroy;
    }

    // Try to find the connection inside nf_conntrack
    if (nfct_query(conntrack_h->ct_handle, NFCT_Q_GET, ct) != 0) {
        if (errno != ENOENT) {
            bpfw_error("Conntrack lookup error: %s (-%d).\n", strerror(errno), errno);
            rc = BPFW_RC_ERROR;
        }
        else
            rc = CONNECTION_NOT_FOUND;
    }
    else
        rc = args.state;

    // Unregister the callback
    nfct_callback_unregister(conntrack_h->ct_handle);

nfct_destroy:
    // Free the conntrack object
    nfct_destroy(ct);

    return rc;
}


void conntrack_destroy(struct conntrack_handle* conntrack_h) {
    // Close/free the conntrack handle
    nfct_close(conntrack_h->ct_handle);

    free(conntrack_h);
}
