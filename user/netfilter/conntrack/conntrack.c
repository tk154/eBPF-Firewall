#include "conntrack.h"
#include "nat.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/netfilter/nf_conntrack_tcp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "../netfilter.h"
#include "../../common_user.h"


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
};


/**
 * Reads timeout values from /proc/sys/net/netfilter/nf_conntrack_<filename>
 * @param filename The timeout value to read
 * @param timeout Where to store the timeout value
 * @returns 0 on success, errno otherwise
 * **/
static int read_conntrack_timeout(const char *filename, __u32 *timeout) {
    const char* base_path = "nf_conntrack_%s";

    char path[64];
    snprintf(path, sizeof(path), base_path, filename);

    return read_netfilter_sysfs_timeout(path, timeout);
}

/**
 * Updates/Refreshes the nf_conntrack timeout
 * @param ct The nf_conntrack entry where to update the timeout
 * @param l4_proto The L4 protocol type (TCP or UDP)
 * **/
static void set_timeout(struct conntrack_handle* conntrack_h, struct nf_conntrack *ct, __u8 l4_proto) {
    __u32 timeout;

    // Determine the timeout for the specific protocol
    switch (l4_proto) {
        case IPPROTO_TCP:
            timeout = conntrack_h->tcp_timeout;
        break;

        case IPPROTO_UDP:
            bool assured = nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_ASSURED;
            timeout = assured ? conntrack_h->udp_stream_timeout : conntrack_h->udp_timeout;
        break;
    }

    // Set the new timeout
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
}


static bool tcp_not_established(__u8 l4_proto, struct nf_conntrack *ct) {
    return l4_proto == IPPROTO_TCP &&
        nfct_get_attr_u8(ct, ATTR_TCP_STATE) != TCP_CONNTRACK_ESTABLISHED;
}


// Callback to retrieve a specific conntrack entry
static int nfct_get_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct nfct_get_cb_args *args = data;
    struct conntrack_handle *conntrack_h = args->conntrack_h;
    struct flow_key_value *flow = args->flow;

    switch (flow->value.state) {
        // If the flow was not marked as offloaded (yet)
        case FLOW_NONE:
            if (tcp_not_established(flow->key.l4_proto, ct))
                // If the flow isn't established yet or anymore,
                // the BPF program shouldn't forward its packages
                break;

            log_key(&flow->key, "\nNew: ");
            
            // Mark the flow as established so that the BPF program can take over now
            // Since the TTL is decremented, we must increment the checksum
            // Check for NAT afterward
            flow->value.state         = FLOW_OFFLOADED;
            flow->value.l3_cksum_diff = htons(0x0100);
            check_nat(ct, flow);
        break;

        // If the flow is currently offloaded
        case FLOW_OFFLOADED:
            if (tcp_not_established(flow->key.l4_proto, ct)) {
                flow->value.state = FLOW_NONE;
                break;
            }

            // If there are no new packages, there is nothing to do for this flow
            if (flow->value.action != ACTION_REDIRECT || flow->value.idle > 0)
                break;

            // Update the nf_conntrack timeout
            set_timeout(conntrack_h, ct, flow->key.l4_proto);

            // Update the edited nf_conntrack entry
            if (nfct_query(conntrack_h->ct_handle, NFCT_Q_UPDATE, ct) != 0) {
                FW_ERROR("Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
                return NFCT_CB_FAILURE;
            }
        break;

        // If the flow is finished
        case FLOW_FINISHED:
            log_key(&flow->key, "\nFin: ");
            flow->value.state = FLOW_NONE;
        break;
    }

    return NFCT_CB_CONTINUE;
}


struct conntrack_handle* conntrack_init() {
    struct conntrack_handle *conntrack_h = (struct conntrack_handle*)malloc(sizeof(struct conntrack_handle));
    if (!conntrack_h) {
        FW_ERROR("Error allocating conntrack handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    // Read TCP and UDP timeout values
    if (read_conntrack_timeout("tcp_timeout_established", &conntrack_h->tcp_timeout) != 0 ||
        read_conntrack_timeout("udp_timeout"            , &conntrack_h->udp_timeout) != 0 ||
        read_conntrack_timeout("udp_timeout_stream"     , &conntrack_h->udp_stream_timeout) != 0)
    {
        goto free;
    }

    // Open a new conntrack handle
	conntrack_h->ct_handle = nfct_open(CONNTRACK, 0);
	if (!conntrack_h->ct_handle) {
		FW_ERROR("Error opening conntrack handle: %s (-%d).\n", strerror(errno), errno);
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
        FW_ERROR("Error allocating conntrack object: %s (-%d).\n",
            strerror(errno), errno);
        return errno;
    }

    // Set the attributes accordingly
    nfct_set_attr_u8 (ct, ATTR_L3PROTO,  AF_INET);
    nfct_set_attr_u8 (ct, ATTR_L4PROTO,  flow->key.l4_proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, flow->key.src_ip);
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, flow->key.dest_ip);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, flow->key.src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, flow->key.dest_port);

    struct nfct_get_cb_args args = { conntrack_h, flow };

    // Register the callback for retrieving single conntrack entries
    if (nfct_callback_register(conntrack_h->ct_handle, NFCT_T_ALL, nfct_get_cb, &args) != 0) {
        FW_ERROR("Error registering conntrack callback: %s (-%d).\n",
            strerror(errno), errno);
    }

    // Try to find the connection inside nf_conntrack
    int rc = nfct_query(conntrack_h->ct_handle, NFCT_Q_GET, ct);
    if (rc != 0)
        rc = errno;

    // Unregister the callback
    nfct_callback_unregister(conntrack_h->ct_handle);

    // Free the conntrack object
    nfct_destroy(ct);

    return rc;
}


void conntrack_destroy(struct conntrack_handle* conntrack_h) {
    // Close/free the conntrack handle
    nfct_close(conntrack_h->ct_handle);

    free(conntrack_h);
}
