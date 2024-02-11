#include "conntrack.h"
#include "nat.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <arpa/inet.h>

#include <linux/netfilter/nf_conntrack_tcp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "../common.h"
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

// For the currently iterated BPF conntrack key and value of the conntrack callbacks
struct conn_key_value { struct conn_key key; struct conn_value value; };

/**
 * Updates the nf_conntrack packet counter from the c_value BPF entry.
 * !!! Doesn't work since libnetfilter_conntrack ignores counter changes !!!
 * @param ct The nf_conntrack entry where to update the packet counter
 * **/
static void update_packet_counter(struct nf_conntrack *ct, struct conntrack_entry* ct_entry) {
    // Retrieve the current nf_conntrack packet/byte counter
    __u64 packets = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
    __u64 bytes   = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);

    // Add the packet/byte counter from the BPF map to the nf_conntrack entry
    nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS, packets + ct_entry->packets);
    nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES,   bytes   + ct_entry->bytes);

    // Reset the packet/byte counter from the BPF map
    ct_entry->packets = 0;
    ct_entry->bytes   = 0;
}

/**
 * Updates/Refreshes the nf_conntrack timeout
 * @param ct The nf_conntrack entry where to update the timeout
 * **/
static void update_timeout(struct nf_conntrack *ct, __u8 l4_proto) {
    __u32 timeout;

    // Determine the timeout for the specific protocol
    switch (l4_proto) {
        case IPPROTO_TCP:  timeout = CONNTRACK_TCP_TIMEOUT_ESTABLISHED; break;
        case IPPROTO_UDP:  timeout = CONNTRACK_UDP_TIMEOUT;             break;
        case IPPROTO_ICMP: timeout = CONNTRACK_ICMP_TIMEOUT;            break;
        default:           timeout = CONNTRACK_GENERIC_TIMEOUT;
    }

    // Set the new timeout
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
}

/**
 * Helper to swap the src and dest IP and the src and dest port of a connection key
 * @param c_key Pointer to the connection key
 * **/
void reverse_conn_key(struct conn_key *c_key) {
	__be32 tmp_ip    = c_key->src_ip;
	c_key->src_ip    = c_key->dest_ip;
	c_key->dest_ip   = tmp_ip;

	__be16 tmp_port  = c_key->src_port;
	c_key->src_port  = c_key->dest_port;
	c_key->dest_port = tmp_port;
}

static int check_nat_and_update_bpf_map(struct nf_conntrack *ct, struct conn_key* c_key, struct conn_value* c_value) {
    // Since the TTL is decremented, we must increment the checksum
    // Check for NAT afterward
    c_value->ct_entry.state = CONN_ESTABLISHED;
    c_value->l3_cksum_diff  = htons(0x0100);
    check_nat(ct, c_key, c_value);

    // Add the conntrack info to the map, stop the nf_conntrack iteration on error
    if (bpf_map_update_elem(map_fd, c_key, c_value, BPF_NOEXIST) != 0) {
        FW_ERROR("Error adding conntrack entry to conntrack map: %s (Code: -%d).\n", strerror(errno), errno);
        return errno;
    }

    return 0;
}

// Callback to retrieve all conntrack entries one after the other
static int ct_dump_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct conn_key   c_key   = {};
    struct conn_value c_value = {};

    // Fill the connection key
    c_key.l4_proto = nfct_get_attr_u8 (ct, ATTR_L4PROTO);
    c_key.src_ip   = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
    c_key.dest_ip  = nfct_get_attr_u32(ct, ATTR_IPV4_DST);

    switch (c_key.l4_proto) {
        case IPPROTO_TCP:
            // Retrieve the current TCP connection state
            __u8 state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);

            // If the connection isn't established yet or anymore,
            // the BPF program shouldn't forward its packages
            if (state != TCP_CONNTRACK_ESTABLISHED)
                return NFCT_CB_CONTINUE;

        case IPPROTO_UDP:
            // Save the ports
            c_key.src_port  = nfct_get_attr_u16(ct, ATTR_PORT_SRC);
            c_key.dest_port = nfct_get_attr_u16(ct, ATTR_PORT_DST);
        break;

        case IPPROTO_ICMP:
            c_key.icmp_type = nfct_get_attr_u8 (ct, ATTR_ICMP_TYPE);
            c_key.icmp_id   = nfct_get_attr_u16(ct, ATTR_ICMP_ID);
        break;

        default:
            // If the protocol is not TCP, UDP or ICMP
            FW_INFO("Protocol %u not implemented yet.\n", c_key.l4_proto);
            return NFCT_CB_CONTINUE;
    }

    if (check_nat_and_update_bpf_map(ct, &c_key, &c_value) != 0)
        return NFCT_CB_FAILURE;

    // We also need to create an entry for the reverse direction
    reverse_conn_key(&c_key);
    c_value = (const struct conn_value) {};

    if (check_nat_and_update_bpf_map(ct, &c_key, &c_value) != 0)
        return NFCT_CB_FAILURE;

	return NFCT_CB_CONTINUE;
}


// Callback to retrieve a specific conntrack entry
static int ct_get_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct conn_key_value *conn = (struct conn_key_value*)data;

    switch (conn->value.ct_entry.state) {
        // If the BPF connection was not marked as established (yet)
        case CONN_NEW:
            if (conn->key.l4_proto == IPPROTO_TCP) {
                __u8 state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);

                // If the connection isn't established yet or anymore, the BPF program shouldn't forward its packages
                if (state != TCP_CONNTRACK_ESTABLISHED)
                    return NFCT_CB_CONTINUE;
            }
            
            // Mark the connection as established so that the BPF program can take over now
            // Since the TTL is decremented, we must increment the checksum
            // Check for NAT afterward
            conn->value.ct_entry.state = CONN_ESTABLISHED;
            conn->value.l3_cksum_diff  = htons(0x0100);
            check_nat(ct, &conn->key, &conn->value);
        break;

        // If the connection is currently established
        case CONN_ESTABLISHED:
            // If there are no new packages, there is nothing to do for this connection
            if (conn->value.ct_entry.packets == 0)
                return NFCT_CB_CONTINUE;

            // Update the nf_conntrack package counter and timeout
            update_packet_counter(ct, &conn->value.ct_entry);
            update_timeout(ct, conn->key.l4_proto);

            // Update the edited nf_conntrack entry
            if (nfct_query(ct_handle, NFCT_Q_UPDATE, ct) != 0) {
                FW_ERROR("Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
                return NFCT_CB_STOP;
            }
        break;

        // If the connection is finished
        case CONN_FIN:
            // For the last time, we might have still received some packages
            if (conn->value.ct_entry.packets == 0)
                return NFCT_CB_CONTINUE;

            // Update the nf_conntrack package counter
            update_packet_counter(ct, &conn->value.ct_entry);

            // Update the edited nf_conntrack entry
            if (nfct_query(ct_handle, NFCT_Q_UPDATE, ct) != 0) {
                FW_ERROR("Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
                return NFCT_CB_STOP;
            }
        break;
    }

    // Update the BPF conntrack entry (the packet counter), break out on error
    if (bpf_map_update_elem(map_fd, &conn->key, &conn->value, BPF_EXIST) != 0) {
        FW_ERROR("Error adding conntrack entry to conntrack map: %s (Code: -%d).\n", strerror(errno), errno);
        return NFCT_CB_STOP;
    }

    return NFCT_CB_CONTINUE;
}


int conntrack_init(struct bpf_object* obj) {
    // Get the file descriptor of the BPF connections map
    map_fd = bpf_object__find_map_fd_by_name(obj, CONN_MAP_NAME);
    if (map_fd < 0) {
        FW_ERROR("Couldn't find map '%s' in %s.\n", CONN_MAP_NAME, bpf_object__name(obj));
        return -1;
    }

    // Open a new conntrack handle
	ct_handle = nfct_open(CONNTRACK, 0);
	if (!ct_handle) {
		FW_ERROR("Error opening conntrack handle: %s (-%d).\n", strerror(errno), errno);
		return errno;
	}

    // Register the callback for the upcoming dump request
	nfct_callback_register(ct_handle, NFCT_T_ALL, ct_dump_callback, NULL);

    // Retrieve all IPv4 conntrack entries
    __u32 family = AF_INET;
	if (nfct_query(ct_handle, NFCT_Q_DUMP, &family) != 0) {
        FW_ERROR("Error dumping conntrack entries: %s (-%d).\n", strerror(errno), errno);

        nfct_callback_unregister(ct_handle);
        nfct_close(ct_handle);

        return errno;
    }

    nfct_callback_unregister(ct_handle);

    return 0;
}


int update_conntrack(struct bpf_object* obj) {
    struct conn_key_value conn;

    // Register the callback for retrieving single conntrack entries
    nfct_callback_register(ct_handle, NFCT_T_ALL, ct_get_callback, &conn); 

    // Retrieve the first key of the BPF conntrack map
    int rc = bpf_map_get_next_key(map_fd, NULL, &conn.key);

    // Iterate through all the connection entries
    while (rc == 0) {
        // Retrieve the connection value of the current key
        if (bpf_map_lookup_elem(map_fd, &conn.key, &conn.value) != 0) {
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
        nfct_set_attr_u8 (ct, ATTR_L4PROTO,  conn.key.l4_proto);
        nfct_set_attr_u32(ct, ATTR_IPV4_SRC, conn.key.src_ip);
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, conn.key.dest_ip);

        switch (conn.key.l4_proto) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
                // Set the ports
                nfct_set_attr_u16(ct, ATTR_PORT_SRC, conn.key.src_port);
                nfct_set_attr_u16(ct, ATTR_PORT_DST, conn.key.dest_port);
            break;

            case IPPROTO_ICMP:
                nfct_set_attr_u8 (ct, ATTR_ICMP_TYPE, conn.key.icmp_type);
                nfct_set_attr_u16(ct, ATTR_ICMP_ID, conn.key.icmp_id);
            break;

            default:
                // If the protocol is not TCP, UDP or ICMP
                FW_INFO("Protocol %hhu not implemented yet.\n", conn.key.l4_proto);
                goto loop_continue;
        }

        // Try to find the connection inside nf_conntrack
        if (nfct_query(ct_handle, NFCT_Q_GET, ct) != 0) {
            /* It could be possible that we have received the package here through the BPF map
             * before it was processed by nf_conntrack, or it has been dropped
             */
            
            // If no connection could be found, it is finished or a timeout occured
            // So delete it from the BPF connection map
            if (bpf_map_delete_elem(map_fd, &conn.key) != 0) {
                FW_ERROR("Error deleting connection entry: %s (-%d).\n", strerror(errno), errno);

                // Free the conntrack object, unregister the callback
                nfct_destroy(ct);
                nfct_callback_unregister(ct_handle);

                return errno;
            }
        }

loop_continue:
        // Free the conntrack object
        nfct_destroy(ct);

        // Retrieve the next key of the connections map
        rc = bpf_map_get_next_key(map_fd, &conn.key, &conn.key);
    }

    // Unregister the callback
    nfct_callback_unregister(ct_handle);

    return 0;
}


void conntrack_destroy() {
    // Close/free the conntrack handle
    nfct_close(ct_handle);
}
