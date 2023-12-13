#include "conntrack.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <arpa/inet.h>

#include <linux/netfilter/nf_conntrack_tcp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "../../common.h"


// Default timeouts from /proc/sys/net/netfilter
#define CONNTRACK_GENERIC_TIMEOUT           600
#define CONNTRACK_TCP_TIMEOUT_ESTABLISHED   7440
#define CONNTRACK_UDP_TIMEOUT               60
#define CONNTRACK_ICMP_TIMEOUT              30


// To store the file descriptor of the BPF connections map
static int map_fd;

// Store the nf_conntrack handle pointer
static struct nfct_handle *ct_handle;

// Store the currently iterated BPF conntrack key and value for the conntrack callbacks
static struct conn_key   c_key;
static struct conn_value c_value;


/**
 * Updates the nf_conntrack packet counter from the c_value BPF entry.
 * !!! Doesn't work since libnetfilter_conntrack ignores counter changes !!!
 * @param ct The nf_conntrack entry where to update the packet counter
 * **/
static void update_packet_counter(struct nf_conntrack *ct) {
    // Retrieve the current nf_conntrack packet/byte counter
    __u64 packets = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
    __u64 bytes   = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);

    // Add the packet/byte counter from the BPF map to the nf_conntrack entry
    nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS, packets + c_value.ct_entry.packets);
    nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES,   bytes   + c_value.ct_entry.bytes);

    // Reset the packet/byte counter from the BPF map
    c_value.ct_entry.packets = 0;
    c_value.ct_entry.bytes   = 0;
}

/**
 * Updates/Refreshes the nf_conntrack timeout
 * @param ct The nf_conntrack entry where to update the timeout
 * **/
static void update_timeout(struct nf_conntrack *ct) {
    __u32 timeout;

    // Determine the timeout for the specific protocol
    switch (c_key.protocol) {
        case IPPROTO_TCP:  timeout = CONNTRACK_TCP_TIMEOUT_ESTABLISHED; break;
        case IPPROTO_UDP:  timeout = CONNTRACK_UDP_TIMEOUT; break;
        case IPPROTO_ICMP: timeout = CONNTRACK_ICMP_TIMEOUT; break;
        default:           timeout = CONNTRACK_GENERIC_TIMEOUT;
    }

    // Set the new timeout
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
}


// Callback to retrieve all conntrack entries one after the other
static int ct_dump_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct conn_key   c_key   = {};
    struct conn_value c_value = {};
    
    // Fill the connection key
    c_key.protocol = nfct_get_attr_u8 (ct, ATTR_L4PROTO);
    c_key.src_ip   = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
    c_key.dest_ip  = nfct_get_attr_u32(ct, ATTR_IPV4_DST);

    switch (c_key.protocol) {
        case IPPROTO_TCP:
            // Retrieve the current TCP connection state
            c_value.ct_entry.state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);

            // If it isn't established, the BPF program shouldn't forward its packages
            if (c_value.ct_entry.state != TCP_CONNTRACK_ESTABLISHED)
                return NFCT_CB_CONTINUE;

        case IPPROTO_UDP:
            c_key.src_port = nfct_get_attr_u16(ct, ATTR_PORT_SRC);
            c_key.dest_port = nfct_get_attr_u16(ct, ATTR_PORT_DST);
        break;

        case IPPROTO_ICMP:
            break;

        default:
            // If the protocol is not TCP, UDP or ICMP
            fprintf(stderr, "Protocol %u not implemented yet.\n", c_key.protocol);
            return NFCT_CB_CONTINUE;
    }

    // Add the conntrack info to the map, stop the nf_conntrack iteration on error
    if (bpf_map_update_elem(map_fd, &c_key, &c_value, BPF_NOEXIST) != 0) {
        fprintf(stderr, "Error adding conntrack entry to conntrack map: %s (Code: -%d).\n", strerror(errno), errno);
        return NFCT_CB_FAILURE;
    }

	return NFCT_CB_CONTINUE;
}


// Callback to retrieve a specific conntrack entry
static int ct_get_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    switch (c_value.ct_entry.state) {
        // If the BPF connection was not marked as established (yet)
        case CONN_NEW:
            if (c_key.protocol == IPPROTO_TCP) {
                __u8 state = nfct_get_attr_u64(ct, ATTR_TCP_STATE);

                // If the connection isn't established yet or anymore, the BPF program shouldn't forward its packages
                if (state != TCP_CONNTRACK_ESTABLISHED)
                    return NFCT_CB_CONTINUE;
            }
            
            // Mark the connection as established so that the BPF program can take over now
            // Since we don't check Firewall entries yet, we just mark it regardless
            c_value.ct_entry.state = CONN_ESTABLISHED;
        break;

        // If the connection is currently established
        case CONN_ESTABLISHED:
            // If there are no new packages, there is nothing to do for this connection
            if (c_value.ct_entry.packets == 0)
                return NFCT_CB_CONTINUE;

            // Update the nf_conntrack package counter and timeout
            update_packet_counter(ct);
            update_timeout(ct);

            // Update the edited nf_conntrack entry
            if (nfct_query(ct_handle, NFCT_Q_UPDATE, ct) != 0) {
                fprintf(stderr, "Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
                return NFCT_CB_FAILURE;
            }
        break;

        // If the connection is finished
        case CONN_FIN:
            // For the last time, we might have still received some packages
            if (c_value.ct_entry.packets == 0)
                return NFCT_CB_CONTINUE;

            // Update the nf_conntrack package counter
            update_packet_counter(ct);

            // Update the edited nf_conntrack entry
            if (nfct_query(ct_handle, NFCT_Q_UPDATE, ct) != 0) {
                fprintf(stderr, "Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
                return NFCT_CB_FAILURE;
            }
        break;
    }

    // Update the BPF conntrack entry (the packet counter), break out on error
    if (bpf_map_update_elem(map_fd, &c_key, &c_value, BPF_EXIST) != 0) {
        fprintf(stderr, "Error adding conntrack entry to conntrack map: %s (Code: -%d).\n", strerror(errno), errno);
        return NFCT_CB_FAILURE;
    }

    return NFCT_CB_CONTINUE;
}


int conntrack_init(struct bpf_object* obj) {
    // Get the file descriptor of the BPF connections map
    map_fd = bpf_object__find_map_fd_by_name(obj, CONN_MAP_NAME);
    if (map_fd < 0) {
        fprintf(stderr, "Couldn't find map '%s' in %s.\n", CONN_MAP_NAME, bpf_object__name(obj));
        return -1;
    }

    // Open a new conntrack handle
	ct_handle = nfct_open(CONNTRACK, 0);
	if (!ct_handle) {
		fprintf(stderr, "Error opening conntrack handle: %s (-%d)\n", strerror(errno), errno);
		return errno;
	}

    // Register the callback for the upcoming dump request
	nfct_callback_register(ct_handle, NFCT_T_ALL, ct_dump_callback, NULL);

    // Retrieve all IPv4 conntrack entries
    __u32 family = AF_INET;
	if (nfct_query(ct_handle, NFCT_Q_DUMP, &family) != 0) {
        fprintf(stderr, "Error dumping conntrack entries: %s (-%d)\n", strerror(errno), errno);
        nfct_close(ct_handle);

        return errno;
    }

    // Register the callback for retrieving single conntrack entries
    nfct_callback_unregister(ct_handle);
    nfct_callback_register(ct_handle, NFCT_T_ALL, ct_get_callback, NULL); 

    return 0;
}


int update_conntrack(struct bpf_object* obj) {
    // Retrieve the first key of the BPF conntrack map
    int rc = bpf_map_get_next_key(map_fd, NULL, &c_key);

    // Iterate through all the connection entries
    while (rc == 0) {
        // Retrieve the connection value of the current key
        if (bpf_map_lookup_elem(map_fd, &c_key, &c_value) != 0) {
            fprintf(stderr, "Error looking up connection entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

        // Create a new conntrack entry object for a lookup
        struct nf_conntrack *ct = nfct_new();
        if (!ct) {
            fprintf(stderr, "nfct_new error: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

        // Set the attributes accordingly
        nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u8(ct, ATTR_L4PROTO, c_key.protocol);
        nfct_set_attr_u32(ct, ATTR_IPV4_SRC, c_key.src_ip);
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, c_key.dest_ip);

        if (c_key.protocol == IPPROTO_TCP || c_key.protocol == IPPROTO_UDP) {
            nfct_set_attr_u16(ct, ATTR_PORT_SRC, c_key.src_port);
            nfct_set_attr_u16(ct, ATTR_PORT_DST, c_key.dest_port);
        }

        // Try to find the connection inside nf_conntrack
        if (nfct_query(ct_handle, NFCT_Q_GET, ct) != 0) {
            /* It could be possible that we have received the package here through the BPF map
             * before it was processed by nf_conntrack
             */
            
            // If no connection could be found, it is finished or a timeout occured
            // So delete it from the BPF connection map
            if (bpf_map_delete_elem(map_fd, &c_key) != 0) {
                fprintf(stderr, "Error deleting connection entry: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }
        }

        // Retrieve the next key of the connections map
        rc = bpf_map_get_next_key(map_fd, &c_key, &c_key);
    }

    return 0;
}


void conntrack_destroy() {
    // Close/free the conntrack handle
    nfct_close(ct_handle);
}
