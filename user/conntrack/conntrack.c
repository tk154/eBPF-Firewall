#include "conntrack.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../../common.h"


#define CONNTRACK_BASE_MATCH \
    "ipv4 %*d %*s %hhu"

#define CONNTRACK_TCP_MATCH \
    "ipv4 %*d %*s %*u %*d %s " \
    "src=%s dst=%s sport=%hu dport=%hu"

#define CONNTRACK_UDP_MATCH \
    "ipv4 %*d %*s %*u %*d " \
    "src=%s dst=%s sport=%hu dport=%hu"

#define CONNTRACK_ICMP_MATCH \
    "ipv4 %*d %*s %*u %*d " \
    "src=%s dst=%s"


// Copied from <netinet/tcp.h>
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING
};

/**
 * Convert the TCP state string to an integer
 * @param state The string containing the TCP state
 * @returns The state as an integer if the string state matched, 0 otherwise
 * **/
static unsigned int tcp_state_str2int(char* state) {
    if (strcmp(state, "ESTABLISHED") == 0)
        return TCP_ESTABLISHED;
    if (strcmp(state, "SYN_SENT") == 0)
        return TCP_SYN_SENT;
    if (strcmp(state, "SYN_RECV") == 0)
        return TCP_SYN_RECV;
    if (strcmp(state, "FIN_WAIT1") == 0)
        return TCP_FIN_WAIT1;
    if (strcmp(state, "FIN_WAIT2") == 0)
        return TCP_FIN_WAIT2;
    if (strcmp(state, "TIME_WAIT") == 0)
        return TCP_TIME_WAIT;
    if (strcmp(state, "CLOSE") == 0)
        return TCP_CLOSE;
    if (strcmp(state, "CLOSE_WAIT") == 0)
        return TCP_CLOSE_WAIT;
    if (strcmp(state, "LAST_ACK") == 0)
        return TCP_LAST_ACK;
    if (strcmp(state, "LISTEN") == 0)
        return TCP_LISTEN;
    if (strcmp(state, "CLOSING") == 0)
        return TCP_CLOSING;

    return 0;
}

/**
 * Parses the given conntrack line and creates a key/value pair for the BPF conntrack map
 * @param ct_line A pointer to the conntrack line string
 * @param key A pointer to where to store the conntrack key
 * @param state A pointer to where to store the conntrack state (only TCP)
 * @returns true, if the given conntrack line was parsed successfully, false otherwise
 * **/
static bool parse_conntrack_line(char* ct_line, struct conntrack_key* key, conntrack_state* state) {
    // Try to retrieve the IPv4 Protocol
    if (sscanf(ct_line, CONNTRACK_BASE_MATCH, &key->protocol) != 1)
        return false;

    // To store the IP strings
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    switch (key->protocol) {
        case IPPROTO_TCP:
            // Retrieve the state, IPs and Ports of the TCP connection
            char state_str[16];
            sscanf(ct_line, CONNTRACK_TCP_MATCH, state_str, src_ip_str, dst_ip_str, &key->src_port, &key->dest_port);

            // Convert the state string to its corresponding int representation
            *state = tcp_state_str2int(state_str);

            break;

        case IPPROTO_UDP:
            // Retrieve the IPs and Ports of the UDP connection
            sscanf(ct_line, CONNTRACK_UDP_MATCH, src_ip_str, dst_ip_str, &key->src_port, &key->dest_port);
            break;

        case IPPROTO_ICMP:
            // Retrieve the IPs of the ICMP connection
            sscanf(ct_line, CONNTRACK_ICMP_MATCH, src_ip_str, dst_ip_str);
            break;

        default:
            // If the protocol is not TCP, UDP or ICMP
            fprintf(stderr, "Protocol %u not implemented yet.\n", key->protocol);
            return false;
    }

    // For Debugging purposes
    printf("Protocol: %hhu\n", key->protocol);
    printf("Source - IP: %s, Port: %hu\n", src_ip_str, key->src_port);
    printf("Destination - IP: %s, Port: %hu\n\n", dst_ip_str, key->dest_port);

    // Convert src and dst IP string to binary form
    inet_pton(AF_INET, src_ip_str, &key->src_ip);
    inet_pton(AF_INET, dst_ip_str, &key->dest_ip);

    // Change the endianness of the ports
    key->src_port = ntohs(key->src_port);
    key->dest_port = ntohs(key->dest_port);

    return true;
}

int read_and_save_conntrack(struct bpf_object* obj) {
    // Get the file descriptor of the conntrack map
    int map_fd = bpf_object__find_map_fd_by_name(obj, CONNTRACK_MAP_NAME);
    if (map_fd < 0) {
        fprintf(stderr, "Couldn't find map '%s' in %s.\n", CONNTRACK_MAP_NAME, bpf_object__name(obj));
        return -1;
    }

    // Open the conntrack file, return on error
    const char* ct_filepath = "/proc/net/nf_conntrack";
    FILE* ct_file = fopen(ct_filepath, "r");
    if (ct_file == NULL) {
        fprintf(stderr, "Error opening %s: %s (Code -%d).\n", ct_filepath, strerror(errno), errno);
        return errno;
    }

    // To save the return code of called functions and a buffer for the read lines
    int rc = 0;
    char ct_line[1024];

    // Read the conntrack file line by line
    while (fgets(ct_line, sizeof(ct_line), ct_file) != NULL) {
        struct conntrack_key key = {};
        conntrack_state state = 0;

        // Parse the conntrack line, continue if not parseable
        if (!parse_conntrack_line(ct_line, &key, &state))
            continue;

        // Add the conntrack info to the map, break out on error
        if (bpf_map_update_elem(map_fd, &key, &state, BPF_NOEXIST) != 0) {
            fprintf(stderr, "Error adding conntrack entry to conntrack map: %s (Code: -%d).\n", strerror(errno), errno);
            rc = errno;

            break;
        }
    }

    fclose(ct_file);

    return rc;
}
