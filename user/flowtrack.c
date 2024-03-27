#include "flowtrack.h"

#include <errno.h>
#include <bpf/bpf.h>
#include <netinet/in.h>

#include "bpf_loader/bpf_loader.h"
#include "netlink/netlink.h"

#include "netfilter/netfilter.h"
#include "netfilter/conntrack/conntrack.h"

#include "common_user.h"


enum flowtrack_destroy {
    FLOWTRACK_DESTROY_ALL,
    FLOWTRACK_DESTROY_NETLINK,
    FLOWTRACK_DESTROY_CONNTRACK,
    FLOWTRACK_DESTROY_BPF_DETACH,
    FLOWTRACK_DESTROY_BPF_UNLOAD
};


static int flow_map_fd;

static unsigned int map_poll_sec;

// Timeouts from /proc/sys/net/netfilter
static __u32 tcp_flow_timeout;
static __u32 udp_flow_timeout;


/**
 * Reads timeout values from /proc/sys/net/netfilter/nf_flowtable_<filename>
 * @param filename The timeout value to read
 * @param timeout Where to store the timeout value
 * @returns 0 on success, errno otherwise
 * **/
static int read_flowtable_timeout(const char *filename, __u32 *timeout) {
    const char* base_path = "nf_flowtable_%s";

    char path[64];
    snprintf(path, sizeof(path), base_path, filename);

    return read_netfilter_sysfs_timeout(path, timeout);
}

static void __flowtrack_destroy(struct cmd_args *args, enum flowtrack_destroy jump) {
    switch (jump) {
        case FLOWTRACK_DESTROY_ALL:
        case FLOWTRACK_DESTROY_NETLINK:
            netlink_destroy();

        case FLOWTRACK_DESTROY_CONNTRACK:
            // De-Init conntrack
            conntrack_destroy();

        case FLOWTRACK_DESTROY_BPF_DETACH:
            // Detach the program from the specified interface names
            bpf_ifs_detach_program(args->if_names, args->if_count);

        case FLOWTRACK_DESTROY_BPF_UNLOAD:
            // Unload the BPF object from the kernel
            bpf_unload_program();
    }
}


int flowtrack_init(struct cmd_args *args) {
    map_poll_sec = args->map_poll_sec;

    // Load the BPF object (including program and maps) into the kernel
    FW_INFO("Loading BPF program into kernel ...\n");

    int rc = bpf_load_program(args->prog_path, args->prog_type);
    if (rc != 0)
        return rc;

    // Get the file descriptor of the BPF flow map
    flow_map_fd = bpf_get_map_fd(FLOW_MAP_NAME);
    if (flow_map_fd < 0) {
        FW_ERROR("Couldn't retrieve '%s' map_fd.\n", FLOW_MAP_NAME);
        __flowtrack_destroy(args, FLOWTRACK_DESTROY_BPF_UNLOAD);

        return ENOENT;
    }

    FW_INFO("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    rc = bpf_ifs_attach_program(args->if_names, args->if_count);
    if (rc != 0) {
        __flowtrack_destroy(args, FLOWTRACK_DESTROY_BPF_UNLOAD);
        return rc;
    }

    // Read the conntrack info and save it inside the BPF conntrack map
    rc = conntrack_init();
    if (rc != 0) {
        __flowtrack_destroy(args, FLOWTRACK_DESTROY_BPF_DETACH);
        return rc;
    }

    rc = netlink_init();
    if (rc != 0) {
        __flowtrack_destroy(args, FLOWTRACK_DESTROY_CONNTRACK);
        return rc;
    }

    // Read TCP and UDP flow timeout values
    if (read_flowtable_timeout("tcp_timeout", &tcp_flow_timeout) != 0 ||
        read_flowtable_timeout("udp_timeout", &udp_flow_timeout) != 0)
    {
        return errno;
    }

    return 0;
}

int flowtrack_update() {
    struct flow_key_value flow;

    // Retrieve the first key of the BPF flow map
    int rc = bpf_map_get_next_key(flow_map_fd, NULL, &flow.key);

    // Iterate through all the flow entries
    while (rc == 0) {
        // Retrieve the flow value of the current key
        if (bpf_map_lookup_elem(flow_map_fd, &flow.key, &flow.value) != 0) {
            FW_ERROR("Error looking up flow entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

        if (flow.key.l4_proto == IPPROTO_TCP && flow.value.idle >= tcp_flow_timeout ||
            flow.key.l4_proto == IPPROTO_UDP && flow.value.idle >= udp_flow_timeout)
        {
            log_key(&flow.key, "\nTim: ");
            
            // If no flow could be found, it is finished or a timeout occured
            // So delete it from the BPF flow map
            if (bpf_map_delete_elem(flow_map_fd, &flow.key) != 0) {
                FW_ERROR("Error deleting flow entry: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }

            goto get_next_key;
        }

        __u8 old_state = flow.value.state;
        rc = conntrack_lookup(&flow);

        if (rc == ENOENT) {
            /* It could be possible that we have received the package here through the BPF map
                * before it was processed by nf_conntrack, or it has been dropped
                */
            log_key(&flow.key, "\nMis: ");
            flow.value.state = FLOW_NONE;
        }
        else if (rc != 0) {
            FW_ERROR("Conntrack lookup error: %s (-%d).\n", strerror(errno), errno);
            return rc;
        }

        __u8 new_state = flow.value.state;
        if (old_state != FLOW_OFFLOADED && new_state == FLOW_OFFLOADED) {
            rc = netlink_get_next_hop(&flow);
            if (rc != 0)
                return rc;
        }

        flow.value.idle += map_poll_sec;

        // Update the BPF flow entry, break out on error
        if (bpf_map_update_elem(flow_map_fd, &flow.key, &flow.value, BPF_EXIST) != 0) {
            FW_ERROR("Error updating flow entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

get_next_key:
        // Retrieve the next key of the flows map
        rc = bpf_map_get_next_key(flow_map_fd, &flow.key, &flow.key);
    }

    if (rc != -ENOENT) {
        FW_ERROR("Error retrieving flow key: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    return 0;
}

void flowtrack_destroy(struct cmd_args *args) {
    __flowtrack_destroy(args, FLOWTRACK_DESTROY_ALL);
}