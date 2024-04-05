#include "flowtrack.h"

#include <errno.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <netinet/in.h>

#include "bpf_loader/bpf_loader.h"
#include "netlink/netlink.h"

#include "netfilter/netfilter.h"
#include "netfilter/conntrack/conntrack.h"

#include "common_user.h"


struct flowtrack_handle {
    int flow_map_fd;
    unsigned int map_poll_sec;

    struct bpf_object_program *bpf;
    struct netlink_handle *netlink_h;
    struct conntrack_handle *conntrack_h;

    // Timeouts from /proc/sys/net/netfilter
    __u32 tcp_flow_timeout;
    __u32 udp_flow_timeout;
};


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


struct flowtrack_handle* flowtrack_init(struct cmd_args *args) {
    struct flowtrack_handle* flowtrack_h = (struct flowtrack_handle*)malloc(sizeof(struct flowtrack_handle));
    if (!flowtrack_h) {
        FW_ERROR("Error allocating flowtrack handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    flowtrack_h->map_poll_sec = args->map_poll_sec;

    // Load the BPF object (including program and maps) into the kernel
    FW_INFO("Loading BPF program into kernel ...\n");

    flowtrack_h->bpf = bpf_load_program(args->prog_path, args->prog_type);
    if (!flowtrack_h->bpf)
        goto free;

    // Get the file descriptor of the BPF flow map
    flowtrack_h->flow_map_fd = bpf_get_map_fd(flowtrack_h->bpf, FLOW_MAP_NAME);
    if (flowtrack_h->flow_map_fd < 0) {
        FW_ERROR("Couldn't retrieve '%s' map_fd.\n", FLOW_MAP_NAME);
        goto bpf_unload_program;
    }

    FW_INFO("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    int rc = args->if_count == 0 ? bpf_attach_program(flowtrack_h->bpf) :
        bpf_ifs_attach_program(flowtrack_h->bpf, args->if_names, args->if_count);

    if (rc != 0)
        goto bpf_unload_program;

    // Read the conntrack info and save it inside the BPF conntrack map
    flowtrack_h->conntrack_h = conntrack_init();
    if (!flowtrack_h->conntrack_h)
        goto bpf_ifs_detach_program;

    flowtrack_h->netlink_h = netlink_init();
    if (!flowtrack_h->netlink_h)
        goto conntrack_destroy;

    // Read TCP and UDP flow timeout values
    if (read_flowtable_timeout("tcp_timeout", &flowtrack_h->tcp_flow_timeout) != 0 ||
        read_flowtable_timeout("udp_timeout", &flowtrack_h->udp_flow_timeout) != 0)
    {
        goto netlink_destroy;
    }

    return flowtrack_h;

netlink_destroy:
    netlink_destroy(flowtrack_h->netlink_h);

conntrack_destroy:
    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

bpf_ifs_detach_program:
    // Detach the program from the specified interface names
    bpf_ifs_detach_program(flowtrack_h->bpf, args->if_names, args->if_count);

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf);

free:
    free(flowtrack_h);

    return NULL;
}

int flowtrack_update(struct flowtrack_handle* flowtrack_h) {
    struct flow_key_value flow;

    // Retrieve the first key of the BPF flow map
    int rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, NULL, &flow.key);

    // Iterate through all the flow entries
    while (rc == 0) {
        // Retrieve the flow value of the current key
        if (bpf_map_lookup_elem(flowtrack_h->flow_map_fd, &flow.key, &flow.value) != 0) {
            FW_ERROR("Error looking up flow entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

        if (flow.key.l4_proto == IPPROTO_TCP && flow.value.idle >= flowtrack_h->tcp_flow_timeout ||
            flow.key.l4_proto == IPPROTO_UDP && flow.value.idle >= flowtrack_h->udp_flow_timeout)
        {
            if (flow.value.state == FLOW_OFFLOADED)
                log_key(&flow.key, "\nTim: ");
            
            // If no flow could be found, it is finished or a timeout occured
            // So delete it from the BPF flow map
            if (bpf_map_delete_elem(flowtrack_h->flow_map_fd, &flow.key) != 0) {
                FW_ERROR("Error deleting flow entry: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }

            goto get_next_key;
        }

        __u8 old_state = flow.value.state;
        rc = conntrack_lookup(flowtrack_h->conntrack_h, &flow);

        if (rc == ENOENT)
            /* It could be possible that we have received the package here through the BPF map
                * before it was processed by nf_conntrack, or it has been dropped
                */
            flow.value.state = FLOW_NONE;
        else if (rc != 0) {
            FW_ERROR("Conntrack lookup error: %s (-%d).\n", strerror(errno), errno);
            return rc;
        }

        __u8 new_state = flow.value.state;
        if (old_state != FLOW_OFFLOADED && new_state == FLOW_OFFLOADED) {
            rc = netlink_get_next_hop(flowtrack_h->netlink_h, &flow);
            if (rc != 0)
                return rc;
        }
        else if (old_state == FLOW_OFFLOADED && new_state != FLOW_OFFLOADED)
            log_key(&flow.key, "\nExp: ");

        flow.value.idle += flowtrack_h->map_poll_sec;

        // Update the BPF flow entry, break out on error
        if (bpf_map_update_elem(flowtrack_h->flow_map_fd, &flow.key, &flow.value, BPF_EXIST) != 0) {
            FW_ERROR("Error updating flow entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

get_next_key:
        // Retrieve the next key of the flows map
        rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, &flow.key, &flow.key);
    }

    if (rc != -ENOENT) {
        FW_ERROR("Error retrieving flow key: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    return 0;
}

void flowtrack_destroy(struct flowtrack_handle* flowtrack_h, struct cmd_args *args) {
    // Detach the program from the specified interface names
    args->if_count == 0 ? bpf_detach_program(flowtrack_h->bpf) :
        bpf_ifs_detach_program(flowtrack_h->bpf, args->if_names, args->if_count);

    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf);

    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

    // De-Init netlink
    netlink_destroy(flowtrack_h->netlink_h);

    free(flowtrack_h);
}
