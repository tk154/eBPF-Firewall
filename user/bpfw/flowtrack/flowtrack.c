#include "flowtrack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include "../bpf/bpf.h"
#include "../conntrack/conntrack.h"
#include "../netlink/netlink.h"

#include "../log/log.h"

#define bpf_flows_for_each_entry(handle, map, key, value, block)    \
    do {                                                            \
        map = handle->flow4_map;                                    \
        bpf_map_for_each_entry(map, key, value, block);             \
        map = handle->flow6_map;                                    \
        bpf_map_for_each_entry(map, key, value, block);             \
    } while (0);


struct flowtrack_handle {
    struct bpf_handle *bpf_h;
    struct netlink_handle *netlink_h;
    struct conntrack_handle *conntrack_h;

    struct netlink_cb link_cb;

    // Flow Timeouts
    struct flow_timeout flow_timeout;
    struct dsa_tag *dsa_tag;

    struct bpf_map *flow4_map, *flow6_map, *user_time_map;
    __u32 map_poll_sec;

    struct map *iface_hooks;
    enum bpf_hook hook;
};


static __u64 time_get_coarse_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

    return ts.tv_sec * (__u64)1e9 + ts.tv_nsec;
}

static __u32 time_ns_to_sec(__u64 ns) {
    return (__u32)(ns / (__u64)1e9);
}

static int update_userspace_time(struct flowtrack_handle *flowtrack_h, __u64 curr_time) {
    unsigned int index = 0;

    struct user_time user = {
        .timeout = (__u64)3e9 * flowtrack_h->map_poll_sec,
        .last_time = curr_time,
        .warned_about_timeout = false
    };

    // Update the BPF flow entry, break out on error
    if (bpf_map_update_entry(flowtrack_h->user_time_map, &index, &user) != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    return BPFW_RC_OK;
}

static int calc_l2_diff(struct flowtrack_handle *flowtrack_h, struct flow *flow) {
    struct dsa_tag *tag = flowtrack_h->dsa_tag;
    enum bpf_hook hook = flowtrack_h->hook;
    char ifname[IF_NAMESIZE];
    __s8 diff = 0;

    if_indextoname(flow->key.ifindex, ifname);
    map_lookup_entry(flowtrack_h->iface_hooks, ifname, &hook);

    if (flow->key.dsa_port)
        diff -= tag->rx_size;
    if (flow->value.next.hop.dsa_port)
        diff += tag->tx_size;

    if ((hook & BPF_HOOK_XDP || flow->key.dsa_port) && flow->key.vlan_id)
        diff -= sizeof(struct vlanhdr);
    if ((hook & BPF_HOOK_XDP || flow->value.next.hop.dsa_port) && flow->value.next.hop.vlan_id)
        diff += sizeof(struct vlanhdr);

    if (flow->key.pppoe_id)
        diff -= sizeof(struct pppoehdr);
    if (flow->value.next.hop.pppoe_id)
        diff += sizeof(struct pppoehdr);

	if ((hook & BPF_HOOK_TC) && diff < 0) {
        bpfw_debug("TC cannot shrink L2 Header (L2 diff = %hhd).\n", diff);
        return EOPNOTSUPP;
    }
    else if (diff)
        bpfw_verbose("L2 diff = %hhd, ", diff);

    flow->value.next.hop.l2_diff = diff;

    return BPFW_RC_OK;
}


static void free_bpf_maps(struct flowtrack_handle *flowtrack_h) {
    bpf_free_map(flowtrack_h->flow4_map);
    bpf_free_map(flowtrack_h->flow6_map);
    bpf_free_map(flowtrack_h->user_time_map);
}

static int get_bpf_maps(struct flowtrack_handle *flowtrack_h) {
    flowtrack_h->flow4_map = bpf_get_map(flowtrack_h->bpf_h, IPV4_FLOW_MAP_NAME);
    flowtrack_h->flow6_map = bpf_get_map(flowtrack_h->bpf_h, IPV6_FLOW_MAP_NAME);
    flowtrack_h->user_time_map = bpf_get_map(flowtrack_h->bpf_h, USERSPACE_TIME_SECTION);
    
    if (!flowtrack_h->flow4_map || !flowtrack_h->flow6_map || !flowtrack_h->user_time_map) {
        free_bpf_maps(flowtrack_h);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

static int new_interface(__u32 ifindex, const char *ifname, void *data) {
    struct flowtrack_handle *flowtrack_h = data;

    return bpf_iface_attach_program(flowtrack_h->bpf_h, flowtrack_h->netlink_h, ifindex, ifname);
}

static int del_interface(__u32 ifindex, const char *ifname, void *data) {
    struct flowtrack_handle *flowtrack_h = data;
    struct flow flow;
    struct bpf_map *flow_map;

    bpf_flows_for_each_entry(flowtrack_h, flow_map, &flow.key, &flow.value, {
        if (flow.key.ifindex == ifindex || flow.value.next.hop.ifindex == ifindex)
            if (bpf_map_delete_entry(flow_map, &flow.key) != BPFW_RC_OK)
                return BPFW_RC_ERROR;
    });
}


static void connection_flowtable_offload(struct flow *flow) {
    if (flow->value.state == STATE_NEW_FLOW)
        bpfw_debug_key("\nConnection is offloaded to flowtable. Cannot read TCP state.\n", &flow->key);
}

static int connection_not_established(struct flow *flow) {
    /* It could be possible that we have received the package here through the BPF map
    *  before it was processed by nf_conntrack, or it has been dropped
    */
    if (flow->value.state == STATE_NEW_FLOW) {
        bpfw_debug_key("\nNon: ", &flow->key);

        flow->value.action = ACTION_NONE;
        bpfw_debug_action("Act: ", flow->value.action);
    }

    return BPFW_RC_OK;
}

static int connection_established(struct flowtrack_handle *flowtrack_h, struct flow *flow, __u32 last_packet_sec_ago) {
    switch (flow->value.state) {
        case STATE_NONE:
            memset(&flow->value.next, 0, sizeof(flow->value.next));

        case STATE_NEW_FLOW:
            bpfw_debug_key("\nCon: ", &flow->key);

            // Since the TTL is decremented, we must increment the checksum for IPv4
            if (flow->key.family == AF_INET)
                flow->value.next.ipv4_cksum_diff = htons(0x0100);

            // Check for NAT
            conntrack_check_nat(flowtrack_h->conntrack_h, flow);
            
            int rc = netlink_get_next_hop(flowtrack_h->netlink_h, flow);
            switch (rc) {
                case BPFW_RC_ERROR:
                    return BPFW_RC_ERROR;

                case ACTION_FORWARD:
                    if (calc_l2_diff(flowtrack_h, flow) != BPFW_RC_OK) {
                        flow->value.action = ACTION_PASS;
                        break;
                    }

                default:
                    flow->value.action = rc;
            }
            
            bpfw_debug_action("Act: ", flow->value.action);
            break;

        case STATE_FORWARD:
            // If there was a new package, update the nf_conntrack timeout
            if (last_packet_sec_ago < flowtrack_h->map_poll_sec &&
                conntrack_update_timeout(flowtrack_h->conntrack_h) != BPFW_RC_OK)
                    return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


static int handle_bpf_entry(struct flowtrack_handle *flowtrack_h, struct bpf_map *flow_map,
                            struct flow *flow, __u32 time_sec)
{
    __u32 flow_time_sec, flow_timeout, last_packet_sec_ago;
    __u8 old_state;
    int rc;

    flow_time_sec = time_ns_to_sec(flow->value.time);
    flow_timeout = flow->key.proto == IPPROTO_TCP ?
        flowtrack_h->flow_timeout.tcp : flowtrack_h->flow_timeout.udp;

    last_packet_sec_ago = time_sec - flow_time_sec;
    if (last_packet_sec_ago >= flow_timeout)
        // Flow timeout occured, so delete it from the BPF map
        return bpf_map_delete_entry(flow_map, &flow->key);

    old_state = flow->value.state;
    rc = conntrack_do_lookup(flowtrack_h->conntrack_h, flow);

    switch (rc) {
        case CT_CONN_FLOWTABLE_OFFLOAD:
            connection_flowtable_offload(flow);

        case CT_CONN_NOT_FOUND:
        case CT_CONN_NOT_ESTABLISHED:
            rc = connection_not_established(flow);
            break;

        case CT_CONN_ESTABLISHED:
            rc = connection_established(flowtrack_h, flow, last_packet_sec_ago);
            conntrack_free_ct_entry(flowtrack_h->conntrack_h);
            break;

        default:
            return BPFW_RC_ERROR;
    }

    if (rc != BPFW_RC_OK || old_state == flow->value.state)
        return rc;

    return bpf_map_update_entry(flow_map, &flow->key, &flow->value);
}

static int update_flows(struct flowtrack_handle* flowtrack_h) {
    struct bpf_map *flow_map;
    struct flow flow;
    __u32 time_sec;
    __u64 time_ns;

    time_ns = time_get_coarse_ns();
    time_sec = time_ns_to_sec(time_ns);

    // Iterate through all the flow entries
    bpf_flows_for_each_entry(flowtrack_h, flow_map, &flow.key, &flow.value, {
        if (handle_bpf_entry(flowtrack_h, flow_map, &flow, time_sec) != BPFW_RC_OK)
            return BPFW_RC_ERROR;
    });

    if (update_userspace_time(flowtrack_h, time_ns) != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    return BPFW_RC_OK;
}

int flowtrack_loop(struct flowtrack_handle* flowtrack_h) {
    while (1) {
        sleep(flowtrack_h->map_poll_sec);

        if (netlink_check_notifications(flowtrack_h->netlink_h,
                flowtrack_h->link_cb, flowtrack_h) != BPFW_RC_OK)
            return BPFW_RC_ERROR;

        if (update_flows(flowtrack_h) != BPFW_RC_OK)
            return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


struct flowtrack_handle* flowtrack_init(struct cmd_args *args) {
    char dsa_proto[DSA_PROTO_MAX_LEN];
    __u32 dsa_switch;
    int rc;

    struct flowtrack_handle* flowtrack_h = (struct flowtrack_handle*)malloc(sizeof(struct flowtrack_handle));
    if (!flowtrack_h) {
        bpfw_error("Error allocating flowtrack handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    flowtrack_h->map_poll_sec = args->map.poll_sec;
    flowtrack_h->flow_timeout = args->flow_timeout;

    flowtrack_h->iface_hooks = args->iface_hooks;
    flowtrack_h->hook = args->hook;

    flowtrack_h->link_cb.newlink = new_interface;
    flowtrack_h->link_cb.dellink = del_interface;

    bpfw_info("Initializing netlink ...\n");

    flowtrack_h->netlink_h = netlink_init(args->auto_attach, args->dsa);
    if (!flowtrack_h->netlink_h)
        goto free;
    
    if (netlink_get_dsa(flowtrack_h->netlink_h, &dsa_switch, dsa_proto) != BPFW_RC_OK)
        goto netlink_destroy;

    bpfw_info("Initializing nf_conntrack ...\n");

    // Read the conntrack info and save it inside the BPF conntrack map
    flowtrack_h->conntrack_h = conntrack_init();
    if (!flowtrack_h->conntrack_h)
        goto netlink_destroy;

    bpfw_info("Opening BPF object ...\n");

    flowtrack_h->bpf_h = bpf_init(args->bpf_obj_path, args->iface_hooks, args->hook);
    if (!flowtrack_h->bpf_h)
        goto conntrack_destroy;

    if (args->rss_prog_name && bpf_init_rss(flowtrack_h->bpf_h, args->rss_prog_name) != BPFW_RC_OK)
        goto bpf_destroy;

    if (args->dsa && bpf_check_dsa(flowtrack_h->bpf_h, dsa_switch, dsa_proto, &flowtrack_h->dsa_tag) != BPFW_RC_OK)
        goto bpf_destroy;

    if (args->map.max_entries != FLOW_MAP_DEFAULT_MAX_ENTRIES) {
        if (bpf_set_map_max_entries(flowtrack_h->bpf_h, IPV4_FLOW_MAP_NAME, args->map.max_entries) != BPFW_RC_OK ||
            bpf_set_map_max_entries(flowtrack_h->bpf_h, IPV6_FLOW_MAP_NAME, args->map.max_entries) != BPFW_RC_OK)
                goto bpf_destroy;
    }

    // Load the BPF object (including program and maps) into the kernel
    bpfw_info("Loading BPF program and attaching to network interfaces ...\n");

    // Attach the program to the specified interface names
    if (bpf_attach_program(flowtrack_h->bpf_h, flowtrack_h->netlink_h, args->auto_attach) != BPFW_RC_OK)
        goto bpf_destroy;

    if (get_bpf_maps(flowtrack_h) != BPFW_RC_OK)
        goto bpf_detach_program;

    return flowtrack_h;

bpf_detach_program:
    // Detach the program from the specified interface names
    bpf_detach_program(flowtrack_h->bpf_h, flowtrack_h->netlink_h, args->auto_attach);

bpf_destroy:
    // Unload the BPF object from the kernel
    bpf_destroy(flowtrack_h->bpf_h);

conntrack_destroy:
    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

netlink_destroy:
    netlink_destroy(flowtrack_h->netlink_h);

free:
    free(flowtrack_h);

    return NULL;
}

void flowtrack_destroy(struct flowtrack_handle* flowtrack_h, struct cmd_args *args) {
    free_bpf_maps(flowtrack_h);

    // Detach the program from the specified interface names
    bpf_detach_program(flowtrack_h->bpf_h, flowtrack_h->netlink_h, args->auto_attach);

    // Unload the BPF object from the kernel
    bpf_destroy(flowtrack_h->bpf_h);

    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

    // De-Init netlink
    netlink_destroy(flowtrack_h->netlink_h);

    free(flowtrack_h);
}
