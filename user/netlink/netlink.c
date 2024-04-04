#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>

#include "../common_user.h"
#include "../../common.h"


// Size of the dynamically allocated Netlink Buffer
#define NL_BUFFER_SIZE MNL_SOCKET_BUFFER_SIZE


// Dynamically allocated buffer for all Netlink requests and responses
static void *nl_buffer;

static struct mnl_socket *nl_socket;


static int get_link(struct netlink_handle* netlink_h, struct flow_value *f_value, __u32 ifindex);

static void log_next_hop(struct next_hop *next_h) {
    if (fw_log_level >= FW_LOG_LEVEL_VERBOSE) {
        char src_mac[18], dest_mac[18];
        snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
            next_h->src_mac[0], next_h->src_mac[1], next_h->src_mac[2],
            next_h->src_mac[3], next_h->src_mac[4], next_h->src_mac[5]);
        snprintf(dest_mac, sizeof(dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
            next_h->dest_mac[0], next_h->dest_mac[1], next_h->dest_mac[2],
            next_h->dest_mac[3], next_h->dest_mac[4], next_h->dest_mac[5]);

        FW_VERBOSE("Hop: %u %s %s", next_h->ifindex, src_mac, dest_mac);

        if (next_h->vlan_id)
            FW_VERBOSE(" %hu\n", next_h->vlan_id);
        else
            FW_VERBOSE("\n");
    }
}

static int mnl_attr_parse_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    tb[mnl_attr_get_type(attr)] = attr;

    return MNL_CB_OK;
}

static int mnl_attr_parse_cb2(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    tb[mnl_attr_get_type(attr)] = attr;

    FW_VERBOSE("%hu\n", mnl_attr_get_type(attr));

    return MNL_CB_OK;
}

static int send_request() {
    struct nlmsghdr *nlh = (struct nlmsghdr*)nl_buffer;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    // Send the request
    if (mnl_socket_sendto(nl_socket, nlh, nlh->nlmsg_len) < 0) {
        FW_ERROR("Error sending netlink request: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(nl_socket, nl_buffer, NL_BUFFER_SIZE);
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
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_buffer);
    nlh->nlmsg_type = RTM_GETROUTE;

    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;

    // Add attributes
    mnl_attr_put_u32(nlh, RTA_IIF, flow->key.ifindex);
    mnl_attr_put_u32(nlh, RTA_SRC, flow->key.src_ip);
    mnl_attr_put_u32(nlh, RTA_DST, *dest_ip);
    mnl_attr_put_u16(nlh, RTA_SPORT, flow->key.src_port);
    mnl_attr_put_u16(nlh, RTA_DPORT, flow->value.n_entry.rewrite_flag & REWRITE_DEST_PORT ?
                                     flow->value.n_entry.dest_port : flow->key.dest_port);
    mnl_attr_put_u8(nlh, RTA_IP_PROTO, flow->key.l4_proto);

    // Send request and receive response
    int rc = send_request();
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIZE(RTM_GETROUTE));
        return rc;
    }

    switch (rtm->rtm_type) {
        case RTN_UNICAST:
            break;

        case RTN_BLACKHOLE:
            flow->value.action = ACTION_DROP;
            return 0;

        case RTN_LOCAL:
            flow->value.action = ACTION_PASS;
            return 0;

        default:
            FW_DEBUG("rtm_type: %u\n", rtm->rtm_type);
            flow->value.action = ACTION_PASS;
            return 0;
    }

    struct nlattr *attr[RTA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*rtm), mnl_attr_parse_cb, attr);

    if (!attr[RTA_OIF]) {
        FW_ERROR("%s didn't return output ifindex.\n", STRINGIZE(RTM_GETROUTE));
        return -1;
    }

    *ifindex = mnl_attr_get_u32(attr[RTA_OIF]);

    if (attr[RTA_GATEWAY])
        *dest_ip = mnl_attr_get_u32(attr[RTA_GATEWAY]);

    flow->value.action = ACTION_REDIRECT;

    return 0;
}

static int get_neigh(struct netlink_handle* netlink_h, struct flow_key_value* flow, __u32 ifindex, void *dest_ip) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_buffer);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family  = AF_INET;
    ndm->ndm_ifindex = ifindex;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put_u32(nlh, NDA_DST, dest_ip);

    // Send request and receive response
    int rc = send_request();
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIZE(RTM_GETNEIGH));
        return rc;
    }

    struct nlattr *attr[NDA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ndm), mnl_attr_parse_cb, attr);

    if (!attr[NDA_LLADDR]) {
        FW_ERROR("%s didn't return destination MAC address.\n", STRINGIZE(RTM_GETNEIGH));
        return -1;
    }

    void *dest_mac = mnl_attr_get_payload(attr[NDA_LLADDR]);
    memcpy(f_value->next_h.dest_mac, dest_mac, ETH_ALEN);

    return 0;
}

static int get_link(struct netlink_handle* netlink_h, struct flow_value *f_value, __u32 ifindex) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request();
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

int netlink_get_next_hop(struct flow_key_value* flow) {
    __u32 ifindex;
    __be32 dest_ip = flow->value.n_entry.rewrite_flag & REWRITE_DEST_IP ?
                     flow->value.n_entry.dest_ip : flow->key.dest_ip;

    int rc = get_route(flow, &ifindex, &dest_ip);
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

int netlink_init() {
    // Open a Netlink socket
    nl_socket = mnl_socket_open(NETLINK_ROUTE);
    if (!nl_socket) {
        FW_ERROR("Error opening netlink socket: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    // Bind the socket
    if (mnl_socket_bind(nl_socket, 0, MNL_SOCKET_AUTOPID) != 0) {
        FW_ERROR("Error binding netlink socket: %s (-%d).\n", strerror(errno), errno);
        mnl_socket_close(nl_socket);

        return errno;
    }

    // Allocate the netlink buffer
    nl_buffer = malloc(NL_BUFFER_SIZE);
    if (!nl_buffer) {
        FW_ERROR("Error allocating netlink buffer: %s (-%d).\n", strerror(errno), errno);
        mnl_socket_close(nl_socket);

        return errno;
    }

    return 0;
}

void netlink_destroy() {
    // Close the socket
    mnl_socket_close(nl_socket);

    free(nl_buffer);
}
