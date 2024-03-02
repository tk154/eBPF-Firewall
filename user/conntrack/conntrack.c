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


// To store the file descriptor of the BPF connections map
static int map_fd;

// Store the nf_conntrack handle pointer
static struct nfct_handle *ct_handle;

// For the currently iterated BPF conntrack key and value of the conntrack callbacks
struct conn_key   c_key;
struct conn_value c_value;

// Timeouts from /proc/sys/net/netfilter
// Note: There are more, for now just basic ones
__u32 tcp_timeout;
__u32 udp_timeout;


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
    switch (c_key.l4_proto) {
        case IPPROTO_TCP: timeout = tcp_timeout; break;
        case IPPROTO_UDP: timeout = udp_timeout; break;
    }

    // Set the new timeout
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
}

// Helper to swap the src and dest IP and the src and dest port of a connection key
static void reverse_conn_key() {
	__be32 tmp_ip   = c_key.src_ip;
	c_key.src_ip    = c_key.dest_ip;
	c_key.dest_ip   = tmp_ip;

	__be16 tmp_port = c_key.src_port;
	c_key.src_port  = c_key.dest_port;
	c_key.dest_port = tmp_port;
}

static inline void log_entry(const char* prefix) {
#ifdef FW_LOG_LEVEL_DEBUG
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c_key.src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &c_key.dest_ip, dest_ip, sizeof(dest_ip));

    FW_DEBUG("%s%hhu %s %s %hu %hu\n", prefix, c_key.l4_proto,
        src_ip, dest_ip, ntohs(c_key.src_port), ntohs(c_key.dest_port));
#endif
}

static int check_nat_and_update_bpf_map(struct nf_conntrack *ct) {
    // Since the TTL is decremented, we must increment the checksum
    // Check for NAT afterward
    c_value.state         = CONN_ESTABLISHED;
    c_value.l3_cksum_diff = htons(0x0100);
    check_nat(ct, &c_key, &c_value);

    // Add the conntrack info to the map, stop the nf_conntrack iteration on error
    if (bpf_map_update_elem(map_fd, &c_key, &c_value, BPF_NOEXIST) != 0) {
        FW_ERROR("Error adding conntrack entry to conntrack map: %s (Code: -%d).\n", strerror(errno), errno);
        return errno;
    }

    return 0;
}

// Callback to retrieve all conntrack entries one after the other
static int ct_dump_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    c_key   = (const struct conn_key)   {};
    c_value = (const struct conn_value) {};

    c_key.l4_proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);

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

        // Ignore other protocols
        default:
            return NFCT_CB_CONTINUE;
    }

    c_key.src_ip  = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
    c_key.dest_ip = nfct_get_attr_u32(ct, ATTR_IPV4_DST);
    log_entry("Dump: ");

    if (check_nat_and_update_bpf_map(ct) != 0)
        return NFCT_CB_FAILURE;

    // We also need to create an entry for the reverse direction
    reverse_conn_key(&c_key);
    c_value = (const struct conn_value) {};

    if (check_nat_and_update_bpf_map(ct) != 0)
        return NFCT_CB_FAILURE;

	return NFCT_CB_CONTINUE;
}


// Callback to retrieve a specific conntrack entry
static int ct_get_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    switch (c_value.state) {
        // If the BPF connection was not marked as established (yet)
        case CONN_NEW:
            if (c_key.l4_proto == IPPROTO_TCP) {
                __u8 state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);

                // If the connection isn't established yet or anymore, the BPF program shouldn't forward its packages
                if (state != TCP_CONNTRACK_ESTABLISHED)
                    return NFCT_CB_CONTINUE;
            }

            log_entry("New: ");
            
            // Mark the connection as established so that the BPF program can take over now
            // Since the TTL is decremented, we must increment the checksum
            // Check for NAT afterward
            c_value.state         = CONN_ESTABLISHED;
            c_value.l3_cksum_diff = htons(0x0100);
            check_nat(ct, &c_key, &c_value);
        break;

        // If the connection is currently established
        case CONN_ESTABLISHED:
            // If there are no new packages, there is nothing to do for this connection
            if (!c_value.update)
                return NFCT_CB_CONTINUE;

            // Update the nf_conntrack timeout
            update_timeout(ct);
            c_value.update = 0;

            // Update the edited nf_conntrack entry
            if (nfct_query(ct_handle, NFCT_Q_UPDATE, ct) != 0) {
                FW_ERROR("Error updating conntrack entry: %s (-%d).\n", strerror(errno), errno);
                return NFCT_CB_STOP;
            }
        break;

        // If the connection is finished
        case CONN_FIN:
            if (!c_value.update)
                return NFCT_CB_CONTINUE;

            log_entry("Fin: ");
            c_value.update = 0;
        break;
    }

    // Update the BPF conntrack entry, break out on error
    if (bpf_map_update_elem(map_fd, &c_key, &c_value, BPF_EXIST) != 0) {
        FW_ERROR("Error updating conntrack entry in conntrack map: %s (-%d).\n", strerror(errno), errno);
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

    // Register the callback for the upcoming dump request
	nfct_callback_register(ct_handle, NFCT_T_ALL, ct_dump_callback, NULL);

    // Retrieve all IPv4 conntrack entries
    __u32 family = AF_INET;
	if (nfct_query(ct_handle, NFCT_Q_DUMP, &family) != 0) {
        FW_ERROR("Error dumping conntrack entries: %s (-%d).\n", strerror(errno), errno);

        conntrack_destroy();

        return errno;
    }

    nfct_callback_unregister(ct_handle);

    // Register the callback for retrieving single conntrack entries
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
        nfct_set_attr_u8 (ct, ATTR_L4PROTO,  c_key.l4_proto);
        nfct_set_attr_u32(ct, ATTR_IPV4_SRC, c_key.src_ip);
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, c_key.dest_ip);
        nfct_set_attr_u16(ct, ATTR_PORT_SRC, c_key.src_port);
        nfct_set_attr_u16(ct, ATTR_PORT_DST, c_key.dest_port);

        // Try to find the connection inside nf_conntrack
        if (nfct_query(ct_handle, NFCT_Q_GET, ct) != 0) {
            /* It could be possible that we have received the package here through the BPF map
             * before it was processed by nf_conntrack, or it has been dropped
             */
            log_entry("Del: ");
            
            // If no connection could be found, it is finished or a timeout occured
            // So delete it from the BPF connection map
            if (bpf_map_delete_elem(map_fd, &c_key) != 0) {
                FW_ERROR("Error deleting connection entry: %s (-%d).\n", strerror(errno), errno);

                // Free the conntrack object
                nfct_destroy(ct);

                return errno;
            }
        }

        // Free the conntrack object
        nfct_destroy(ct);

        // Retrieve the next key of the connections map
        rc = bpf_map_get_next_key(map_fd, &c_key, &c_key);
    }

    return 0;
}


void conntrack_destroy() {
    // Unregister the callback
    nfct_callback_unregister(ct_handle);

    // Close/free the conntrack handle
    nfct_close(ct_handle);
}
