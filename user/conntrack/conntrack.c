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

#include "../netlink/netlink.h"

#include "../common_user.h"
#include "../../common.h"


// To store the file descriptor of the BPF connections map
static int map_fd;

// Store the nf_conntrack handle pointer
static struct nfct_handle *ct_handle;

// For the currently iterated BPF conntrack key and value of the conntrack callbacks
static struct flow_key   f_key;
static struct flow_value f_value;

// Timeouts from /proc/sys/net/netfilter
// Note: There are more, for now just basic ones
static __u32 tcp_timeout;
static __u32 udp_timeout;


static void log_entry(const char* prefix) {
    if (fw_log_level >= FW_LOG_LEVEL_DEBUG) {
        char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &f_key.src_ip, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &f_key.dest_ip, dest_ip, sizeof(dest_ip));

        FW_DEBUG("%s%u %hhu %s %hu %s %hu\n", prefix, f_key.ifindex, f_key.l4_proto,
            src_ip, ntohs(f_key.src_port), dest_ip, ntohs(f_key.dest_port));
    }
}

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
 * **/
static void update_timeout(struct nf_conntrack *ct) {
    __u32 timeout;

    // Determine the timeout for the specific protocol
    switch (f_key.l4_proto) {
        case IPPROTO_TCP: timeout = tcp_timeout; break;
        case IPPROTO_UDP: timeout = udp_timeout; break;
    }

    // Set the new timeout
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
}


// Callback to retrieve a specific conntrack entry
static int ct_get_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    switch (f_value.state) {
        // If the flow was not marked as offloaded (yet)
        case FLOW_NONE:
            if (f_key.l4_proto == IPPROTO_TCP &&
                nfct_get_attr_u8(ct, ATTR_TCP_STATE) != TCP_CONNTRACK_ESTABLISHED)
            {
                // If the flow isn't established yet or anymore,
                // the BPF program shouldn't forward its packages
                return NFCT_CB_CONTINUE;
            }

            log_entry("\nNew: ");
            
            // Mark the flow as established so that the BPF program can take over now
            // Since the TTL is decremented, we must increment the checksum
            // Check for NAT afterward
            f_value.state         = FLOW_OFFLOADED;
            f_value.l3_cksum_diff = htons(0x0100);
            check_nat(ct, &f_key, &f_value);
            
            if (get_next_hop(&f_key, &f_value) != 0)
                return NFCT_CB_STOP;
        break;

        // If the flow is currently established
        case FLOW_OFFLOADED:
            if (f_key.l4_proto == IPPROTO_TCP &&
                nfct_get_attr_u8(ct, ATTR_TCP_STATE) != TCP_CONNTRACK_ESTABLISHED)
            {
                f_value.state = FLOW_NONE;
                break;
            }

            // If there are no new packages, there is nothing to do for this flow
            if (!f_value.update)
                return NFCT_CB_CONTINUE;

            // Update the nf_conntrack timeout
            update_timeout(ct);
            f_value.update = 0;

            // Update the edited nf_conntrack entry
            if (nfct_query(ct_handle, NFCT_Q_UPDATE, ct) != 0) {
                FW_ERROR("Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
                return NFCT_CB_STOP;
            }
        break;

        // If the flow is finished
        case FLOW_FINISHED:
            log_entry("\nFin: ");
            f_value.state = FLOW_NONE;
        break;
    }

    // Update the BPF conntrack entry, break out on error
    if (bpf_map_update_elem(map_fd, &f_key, &f_value, BPF_EXIST) != 0) {
        FW_ERROR("Error updating conntrack entry in conntrack map: %s (-%d).\n", strerror(errno), errno);
        return NFCT_CB_STOP;
    }

    return NFCT_CB_CONTINUE;
}


int conntrack_init(struct bpf_object* obj) {
    // Get the file descriptor of the BPF connections map
    map_fd = bpf_object__find_map_fd_by_name(obj, FLOW_MAP_NAME);
    if (map_fd < 0) {
        FW_ERROR("Couldn't find map '%s' in %s.\n", FLOW_MAP_NAME, bpf_object__name(obj));
        return -1;
    }

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

    // Register the callback for retrieving single conntrack entries
    nfct_callback_register(ct_handle, NFCT_T_ALL, ct_get_callback, NULL); 

    return 0;
}


int update_conntrack(struct bpf_object* obj) {
    // Retrieve the first key of the BPF conntrack map
    int rc = bpf_map_get_next_key(map_fd, NULL, &f_key);

    // Iterate through all the connection entries
    while (rc == 0) {
        // Retrieve the connection value of the current key
        if (bpf_map_lookup_elem(map_fd, &f_key, &f_value) != 0) {
            FW_ERROR("Error looking up connection entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

        // Create a new conntrack entry object for a lookup
        struct nf_conntrack *ct = nfct_new();
        if (!ct) {
            FW_ERROR("nfct_new error: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

        // Set the attributes accordingly
        nfct_set_attr_u8 (ct, ATTR_L3PROTO,  AF_INET);
        nfct_set_attr_u8 (ct, ATTR_L4PROTO,  f_key.l4_proto);
        nfct_set_attr_u32(ct, ATTR_IPV4_SRC, f_key.src_ip);
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, f_key.dest_ip);
        nfct_set_attr_u16(ct, ATTR_PORT_SRC, f_key.src_port);
        nfct_set_attr_u16(ct, ATTR_PORT_DST, f_key.dest_port);

        // Try to find the connection inside nf_conntrack
        if (nfct_query(ct_handle, NFCT_Q_GET, ct) != 0) {
            /* It could be possible that we have received the package here through the BPF map
             * before it was processed by nf_conntrack, or it has been dropped
             */
            log_entry("\nDel: ");
            
            // If no connection could be found, it is finished or a timeout occured
            // So delete it from the BPF connection map
            if (bpf_map_delete_elem(map_fd, &f_key) != 0) {
                FW_ERROR("Error deleting connection entry: %s (-%d).\n", strerror(errno), errno);
                rc = errno;
            }
        }

        // Free the conntrack object
        nfct_destroy(ct);

        CHECK_RC(rc);

        // Retrieve the next key of the connections map
        rc = bpf_map_get_next_key(map_fd, &f_key, &f_key);
    }

    return 0;
}


void conntrack_destroy() {
    // Unregister the callback
    nfct_callback_unregister(ct_handle);

    // Close/free the conntrack handle
    nfct_close(ct_handle);
}
