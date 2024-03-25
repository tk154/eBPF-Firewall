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

#include "../common_user.h"
#include "../../common.h"


// To store the file descriptor of the BPF flow map
static int map_fd;

// Store the nf_conntrack handle pointer
static struct nfct_handle *ct_handle;

// Timeouts from /proc/sys/net/netfilter
// Note: There are more, for now just basic ones
static __u32 tcp_timeout;
static __u32 udp_timeout;


/**
 * Reads timeout values from /proc/sys/net/netfilter/nf_conntrack_<filename>
 * @param filename The timeout value to read
 * @param timeout Where to store the timeout value
 * @returns 0 on success, errno otherwise
 * **/
static int read_timeout(const char *filename, __u32 *timeout) {
    const char* base_path = "/proc/sys/net/netfilter/nf_conntrack_%s";

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
    *timeout = strtol(buffer, NULL, 10);

    return 0;
}

/**
 * Updates/Refreshes the nf_conntrack timeout
 * @param ct The nf_conntrack entry where to update the timeout
 * @param l4_proto The L4 protocol type (TCP or UDP)
 * **/
static void set_timeout(struct nf_conntrack *ct, __u8 l4_proto) {
    __u32 timeout;

    // Determine the timeout for the specific protocol
    switch (l4_proto) {
        case IPPROTO_TCP: timeout = tcp_timeout; break;
        case IPPROTO_UDP: timeout = udp_timeout; break;
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
    struct flow_key_value *flow = data;

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
            if (!flow->value.update)
                break;

            // Update the nf_conntrack timeout
            set_timeout(ct, flow->key.l4_proto);

            // Update the edited nf_conntrack entry
            if (nfct_query(ct_handle, NFCT_Q_UPDATE, ct) != 0) {
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


int conntrack_init() {
    // Read TCP and UDP timeout values
    if (read_timeout("tcp_timeout_established", &tcp_timeout) != 0 ||
        read_timeout("udp_timeout"            , &udp_timeout) != 0)
    {
        return errno;
    }

    // Open a new conntrack handle
	ct_handle = nfct_open(CONNTRACK, 0);
	if (!ct_handle) {
		FW_ERROR("Error opening conntrack handle: %s (-%d).\n", strerror(errno), errno);
		return errno;
	}

    return 0;
}


int conntrack_lookup(struct flow_key_value *flow) {
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

    // Register the callback for retrieving single conntrack entries
    if (nfct_callback_register(ct_handle, NFCT_T_ALL, nfct_get_cb, flow) != 0) {
        FW_ERROR("Error registering conntrack callback: %s (-%d).\n",
            strerror(errno), errno);
    }

    // Try to find the connection inside nf_conntrack
    int rc = nfct_query(ct_handle, NFCT_Q_GET, ct);
    if (rc != 0)
        rc = errno;

    // Unregister the callback
    nfct_callback_unregister(ct_handle);

    // Free the conntrack object
    nfct_destroy(ct);

    return rc;
}


void conntrack_destroy() {
    // Close/free the conntrack handle
    nfct_close(ct_handle);
}
