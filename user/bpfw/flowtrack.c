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

#ifdef OPENWRT_UCODE
#include "ucode/ucode.h"
#endif


struct flowtrack_handle {
    int flow_map_fd;
    unsigned int map_poll_sec;

    struct bpf_handle *bpf;
    struct netlink_handle *netlink_h;
    struct conntrack_handle *conntrack_h;

#ifdef OPENWRT_UCODE
    struct ucode_handle *ucode_h;
#endif

    // Timeouts from /proc/sys/net/netfilter
    __u32 tcp_flow_timeout;
    __u32 udp_flow_timeout;
};


static char* action2str[] = {
    "None", "Pass", "Drop", "Redirect"
};

static void log_action(__u8 action) {
    FW_DEBUG("Act: %s\n", action2str[action]);
}

/**
 * Reads timeout values from /proc/sys/net/netfilter/nf_flowtable_<filename>
 * @param filename The timeout value to read
 * @param timeout Where to store the timeout value
 * @returns 0 on success, errno otherwise
 * **/
static int read_flowtable_timeout(const char *filename, __u32 *timeout) {
    const char* base_path = "flowtable_%s";

    char path[64];
    snprintf(path, sizeof(path), base_path, filename);

    return netfilter_sysfs_read(path, timeout);
}


struct flowtrack_handle* flowtrack_init(struct cmd_args *args) {
    struct flowtrack_handle* flowtrack_h = (struct flowtrack_handle*)malloc(sizeof(struct flowtrack_handle));
    if (!flowtrack_h) {
        FW_ERROR("Error allocating flowtrack handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    flowtrack_h->map_poll_sec = args->map_poll_sec;

    FW_INFO("Initializing netlink ...\n");

    flowtrack_h->netlink_h = netlink_init();
    if (!flowtrack_h->netlink_h)
        goto free;

    // Load the BPF object (including program and maps) into the kernel
    FW_INFO("Loading BPF program into kernel ...\n");

    flowtrack_h->bpf = bpf_load_program(args->prog_path, args->prog_type, flowtrack_h->netlink_h, args->dsa);
    if (!flowtrack_h->bpf)
        goto netlink_destroy;

    // Get the file descriptor of the BPF flow map
    flowtrack_h->flow_map_fd = bpf_get_map_fd(flowtrack_h->bpf, FLOW_MAP_NAME);
    if (flowtrack_h->flow_map_fd < 0) {
        FW_ERROR("Couldn't retrieve '%s' map_fd.\n", FLOW_MAP_NAME);
        goto bpf_unload_program;
    }

    FW_INFO("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    int rc = args->if_count == 0 ? bpf_attach_program(flowtrack_h->bpf, args->xdp_flags, flowtrack_h->netlink_h) :
        bpf_ifs_attach_program(flowtrack_h->bpf, args->if_names, args->if_count, args->xdp_flags);

    if (rc != 0)
        goto bpf_unload_program;

    FW_INFO("Initializing nf_conntrack ...\n");

    // Read the conntrack info and save it inside the BPF conntrack map
    flowtrack_h->conntrack_h = conntrack_init();
    if (!flowtrack_h->conntrack_h)
        goto bpf_ifs_detach_program;

#ifdef OPENWRT_UCODE
    FW_INFO("Initializing ucode ...\n");

    flowtrack_h->ucode_h = ucode_init();
    if (!flowtrack_h->ucode_h)
        goto conntrack_destroy;
#endif

    // Read TCP and UDP flow timeout values
    if (read_flowtable_timeout("tcp_timeout", &flowtrack_h->tcp_flow_timeout) != 0 ||
        read_flowtable_timeout("udp_timeout", &flowtrack_h->udp_flow_timeout) != 0)
    {
        goto ucode_destroy;
    }

    return flowtrack_h;

ucode_destroy:
#ifdef OPENWRT_UCODE
    ucode_destroy(flowtrack_h->ucode_h);
#endif

conntrack_destroy:
    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

bpf_ifs_detach_program:
    // Detach the program from the specified interface names
    args->if_count == 0 ? bpf_detach_program(flowtrack_h->bpf, args->xdp_flags, flowtrack_h->netlink_h) :
        bpf_ifs_detach_program(flowtrack_h->bpf, args->if_names, args->if_count, args->xdp_flags);

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf);

netlink_destroy:
    netlink_destroy(flowtrack_h->netlink_h);

free:
    free(flowtrack_h);

    return NULL;
}

int flowtrack_update(struct flowtrack_handle* flowtrack_h) {
    struct flow_key_value flow;

    // Retrieve the first key of the BPF flow map
    int bpf_rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, NULL, &flow.key);

    // Iterate through all the flow entries
    while (bpf_rc == 0) {
        // Retrieve the flow value of the current key
        if (bpf_map_lookup_elem(flowtrack_h->flow_map_fd, &flow.key, &flow.value) != 0) {
            FW_ERROR("Error looking up flow entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

        __u32 idle = flow.value.idle + flowtrack_h->map_poll_sec;

        if (flow.key.proto == IPPROTO_TCP && idle >= flowtrack_h->tcp_flow_timeout ||
            flow.key.proto == IPPROTO_UDP && idle >= flowtrack_h->udp_flow_timeout)
        {
            // Flow timeout occured, so delete it from the BPF map
            if (bpf_map_delete_elem(flowtrack_h->flow_map_fd, &flow.key) != 0) {
                FW_ERROR("Error deleting flow entry: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }

            goto get_next_key;
        }

        int ct_rc = conntrack_lookup(flowtrack_h->conntrack_h, &flow);
        switch (ct_rc) {
            case CONNECTION_NOT_FOUND:
#ifdef OPENWRT_UCODE
                if (flow.value.action == ACTION_NONE) {
                    int nl_rc = netlink_get_route(flowtrack_h->netlink_h, &flow);
                    if (nl_rc != 0)
                        return nl_rc;

                    if (flow.value.action != ACTION_DROP) {
                        int uc_rc = ucode_match_rule(flowtrack_h->ucode_h, &flow);
                        if (uc_rc != 0)
                            return uc_rc;
                    }
                }
            break;
#endif

            case CONNECTION_NOT_ESTABLISHED:
                /* It could be possible that we have received the package here through the BPF map
                *  before it was processed by nf_conntrack, or it has been dropped
                */
                flow.value.action = ACTION_NONE;
            break;

            case CONNECTION_ESTABLISHED:
                if (flow.value.action == ACTION_NONE) {
                    int nl_rc = netlink_get_next_hop(flowtrack_h->netlink_h, &flow);
                    if (nl_rc != 0)
                        return nl_rc;

                    log_action(flow.value.action);
                }
            break;

            default:
                return -ct_rc;
        }

        flow.value.idle = idle;

        // Update the BPF flow entry, break out on error
        if (bpf_map_update_elem(flowtrack_h->flow_map_fd, &flow.key, &flow.value, BPF_EXIST) != 0) {
            FW_ERROR("Error updating flow entry: %s (-%d).\n", strerror(errno), errno);
            return errno;
        }

get_next_key:
        // Retrieve the next key of the flows map
        bpf_rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, &flow.key, &flow.key);
    }

    if (bpf_rc != -ENOENT) {
        FW_ERROR("Error retrieving flow key: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    return 0;
}

void flowtrack_destroy(struct flowtrack_handle* flowtrack_h, struct cmd_args *args) {
#ifdef OPENWRT_UCODE
    // De-Init ucode
    ucode_destroy(flowtrack_h->ucode_h);
#endif

    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf);

    // Detach the program from the specified interface names
    args->if_count == 0 ? bpf_detach_program(flowtrack_h->bpf, args->xdp_flags, flowtrack_h->netlink_h) :
        bpf_ifs_detach_program(flowtrack_h->bpf, args->if_names, args->if_count, args->xdp_flags);

    // De-Init netlink
    netlink_destroy(flowtrack_h->netlink_h);

    free(flowtrack_h);
}
