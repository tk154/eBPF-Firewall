#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include <net/if.h>
#include <libmnl/libmnl.h>

#include "../common_user.h"


struct netlink_handle {
    struct mnl_socket *nl_socket;
    size_t nl_buffer_size;

    // Flexible buffer for all Netlink requests and responses
    char nl_buffer[];
};


static int get_link(struct netlink_handle* netlink_h, struct flow_value *f_value, __u32 ifindex);

static void log_next_hop(struct next_hop *next_h) {
    if (fw_log_level >= FW_LOG_LEVEL_VERBOSE) {
        char ifname[IF_NAMESIZE];
        if_indextoname(next_h->ifindex, ifname);

        FW_VERBOSE("Hop: %s", ifname);

        if (next_h->vlan_id)
            FW_VERBOSE(" %hu", next_h->vlan_id);

        FW_VERBOSE(" %02x:%02x:%02x:%02x:%02x:%02x"
                   " %02x:%02x:%02x:%02x:%02x:%02x\n",
            next_h->src_mac[0], next_h->src_mac[1], next_h->src_mac[2],
            next_h->src_mac[3], next_h->src_mac[4], next_h->src_mac[5], 
            next_h->dest_mac[0], next_h->dest_mac[1], next_h->dest_mac[2],
            next_h->dest_mac[3], next_h->dest_mac[4], next_h->dest_mac[5]);
    }
}


void mnl_attr_put_ip(struct nlmsghdr *nlh, uint16_t type, void *ip, __u8 family) {
    switch (family) {
        case AF_INET:
            return mnl_attr_put(nlh, type, 4, ip);
        case AF_INET6:
            return mnl_attr_put(nlh, type, 16, ip);
    }
}

static int mnl_attr_parse_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    tb[mnl_attr_get_type(attr)] = attr;

    return MNL_CB_OK;
}

static int send_request(struct netlink_handle* netlink_h) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)netlink_h->nl_buffer;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    // Send the request
    if (mnl_socket_sendto(netlink_h->nl_socket, nlh, nlh->nlmsg_len) < 0) {
        FW_ERROR("Error sending netlink request: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(netlink_h->nl_socket, netlink_h->nl_buffer, netlink_h->nl_buffer_size);
    if (nbytes < 0) {
        FW_ERROR("Error receiving netlink response: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
        FW_ERROR("Netlink request error: %s (-%d).\n", strerror(-err->error), -err->error);

        return -err->error;
    }

    return 0;
}

static int bridge_get_lower(struct netlink_handle* netlink_h, struct flow_value *f_value, __u32 ifindex) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family = PF_BRIDGE;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put(nlh, NDA_LLADDR, ETH_ALEN, f_value->next_h.dest_mac);
    mnl_attr_put_u32(nlh, NDA_MASTER, ifindex);

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIFY(RTM_GETNEIGH));
        return rc;
    }

    return get_link(netlink_h, f_value, ndm->ndm_ifindex);
}

static int parse_vlan_if(struct netlink_handle* netlink_h, struct nlattr **ifla_info, __u32 phy_ifindex, struct flow_value *f_value) {
    if (f_value->next_h.vlan_id) {
        f_value->action = ACTION_PASS;
        return 0;
    }

    struct nlattr *ifla_vlan[IFLA_VLAN_MAX + 1] = {};
    mnl_attr_parse_nested(ifla_info[IFLA_INFO_DATA], mnl_attr_parse_cb, ifla_vlan);

    __u16 vlan_proto = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_PROTOCOL]);
    if (vlan_proto != ntohs(ETH_P_8021Q)) {
        f_value->action = ACTION_PASS;
        return 0;
    }

    f_value->next_h.vlan_id = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_ID]);

    return get_link(netlink_h, f_value, phy_ifindex);
}

static int get_route(struct netlink_handle* netlink_h, struct flow_key_value* flow, __u32 *ifindex, void *dest_ip) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETROUTE;

    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = flow->key.family;

    // Add attributes
    mnl_attr_put_u8 (nlh, RTA_IP_PROTO, flow->key.proto);
    mnl_attr_put_ip (nlh, RTA_SRC, flow->key.src_ip, flow->key.family);
    mnl_attr_put_ip (nlh, RTA_DST, dest_ip, flow->key.family);
    mnl_attr_put_u16(nlh, RTA_SPORT, flow->key.src_port);
    mnl_attr_put_u16(nlh, RTA_DPORT, flow->value.n_entry.rewrite_flag & REWRITE_DEST_PORT ?
                                     flow->value.n_entry.dest_port : flow->key.dest_port);
    mnl_attr_put_u32(nlh, RTA_IIF, flow->key.ifindex);

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIFY(RTM_GETROUTE));
        return rc;
    }

    switch (rtm->rtm_type) {
        case RTN_UNICAST:
            break;

        case RTN_BLACKHOLE:
            flow->value.action = ACTION_DROP;
            return 0;

        default:
            flow->value.action = ACTION_PASS;
            return 0;
    }

    struct nlattr *attr[RTA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*rtm), mnl_attr_parse_cb, attr);

    if (!attr[RTA_OIF]) {
        FW_ERROR("%s didn't return output ifindex.\n", STRINGIFY(RTM_GETROUTE));
        return -1;
    }

    *ifindex = mnl_attr_get_u32(attr[RTA_OIF]);

    if (attr[RTA_GATEWAY]) {
        void *gateway = mnl_attr_get_payload(attr[RTA_GATEWAY]);
        ipcpy(dest_ip, gateway, flow->key.family);
    }

    flow->value.action = ACTION_REDIRECT;

    return 0;
}

static int get_neigh(struct netlink_handle* netlink_h, struct flow_key_value* flow, __u32 ifindex, void *dest_ip) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family  = flow->key.family;
    ndm->ndm_ifindex = ifindex;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put_ip(nlh, RTA_DST, dest_ip, flow->key.family);

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIFY(RTM_GETNEIGH));
        return rc;
    }

    struct nlattr *attr[NDA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ndm), mnl_attr_parse_cb, attr);

    if (!attr[NDA_LLADDR]) {
        FW_ERROR("%s didn't return destination MAC address.\n", STRINGIFY(RTM_GETNEIGH));
        return -1;
    }

    void *dest_mac = mnl_attr_get_payload(attr[NDA_LLADDR]);
    memcpy(flow->value.next_h.dest_mac, dest_mac, ETH_ALEN);

    return 0;
}

static int get_link(struct netlink_handle* netlink_h, struct flow_value *f_value, __u32 ifindex) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIFY(RTM_GETLINK));
        return rc;
    }

    struct nlattr *attr[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, attr);

    if (attr[IFLA_LINKINFO]) {
        struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
        mnl_attr_parse_nested(attr[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

        if (ifla_info[IFLA_INFO_KIND]) {
            const char *if_type = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);
            if (strcmp(if_type, "bridge") == 0)
                return bridge_get_lower(netlink_h, f_value, ifindex);

            if (strcmp(if_type, "vlan") == 0) {
                __u32 phy_ifindex = mnl_attr_get_u32(attr[IFLA_LINK]);
                return parse_vlan_if(netlink_h, ifla_info, phy_ifindex, f_value);
            }
        }
    }

    if (!attr[IFLA_ADDRESS]) {
        FW_ERROR("%s didn't return interface MAC address.\n", STRINGIFY(RTM_GETLINK));
        return -1;
    }

    void *if_mac = mnl_attr_get_payload(attr[IFLA_ADDRESS]);
    memcpy(f_value->next_h.src_mac, if_mac, ETH_ALEN);

    f_value->next_h.ifindex = ifindex;

    return 0;
}

int netlink_get_next_hop(struct netlink_handle* netlink_h, struct flow_key_value* flow) {
    __u32 ifindex;
    __u8 dest_ip[flow->key.family == AF_INET ? 4 : 16];

    ipcpy(dest_ip, flow->value.n_entry.rewrite_flag & REWRITE_DEST_IP ?
        flow->value.n_entry.dest_ip : flow->key.dest_ip, flow->key.family);

    int rc = get_route(netlink_h, flow, &ifindex, dest_ip);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    rc = get_neigh(netlink_h, flow, ifindex, dest_ip);
    if (rc != 0)
        return rc;

    rc = get_link(netlink_h, &flow->value, ifindex);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    log_next_hop(&flow->value.next_h);

    return 0;
}

struct netlink_handle* netlink_init() {
    size_t nl_buffer_size = MNL_SOCKET_BUFFER_SIZE;

    struct netlink_handle *netlink_h = malloc(sizeof(struct netlink_handle) + nl_buffer_size);
    if (!netlink_h) {
        FW_ERROR("Error allocating netlink handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    netlink_h->nl_buffer_size = nl_buffer_size;

    // Open a Netlink socket
    netlink_h->nl_socket = mnl_socket_open(NETLINK_ROUTE);
    if (!netlink_h->nl_socket) {
        FW_ERROR("Error opening netlink socket: %s (-%d).\n", strerror(errno), errno);
        goto free;
    }

    // Bind the socket
    if (mnl_socket_bind(netlink_h->nl_socket, 0, MNL_SOCKET_AUTOPID) != 0) {
        FW_ERROR("Error binding netlink socket: %s (-%d).\n", strerror(errno), errno);
        goto mnl_socket_close;
    }

    return netlink_h;

mnl_socket_close:
    mnl_socket_close(netlink_h->nl_socket);

free:
    free(netlink_h);

    return NULL;
}

void netlink_destroy(struct netlink_handle* netlink_h) {
    // Close the socket
    mnl_socket_close(netlink_h->nl_socket);

    free(netlink_h);
}
