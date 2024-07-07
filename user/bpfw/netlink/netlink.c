#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>

#include "netlink.h"
#include "pppoe/pppoe.h"

#define NUD_VALID (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE | NUD_DELAY)


struct netlink_handle {
    struct mnl_socket *nl_socket;
    size_t nl_buffer_size;
    __u32 nl_seq;

    struct pppoe_device pppoe;

    // Flexible buffer for all Netlink requests and responses
    __u8 nl_buffer[];
};

struct dump_cb {
    mnl_cb_t func;
    void *data;
};


//static int get_link(struct netlink_handle *netlink_h, struct flow_key_value *flow, __u32 ifindex, void *dest_ip, bool dsa);

static bool mac_not_set(__u8 *mac) {
    return !mac[0] && !mac[1] && !mac[2]
        && !mac[3] && !mac[4] && !mac[5];
}

static int netlink_set_strict_check(struct netlink_handle *netlink_h, int enable) {
	return setsockopt(mnl_socket_get_fd(netlink_h->nl_socket), SOL_NETLINK,
        NETLINK_GET_STRICT_CHK, &enable, sizeof(enable));
}

static void mnl_attr_put_ip(struct nlmsghdr *nlh, uint16_t type, void *ip, __u8 family) {
    switch (family) {
        case AF_INET:
            return mnl_attr_put(nlh, type, IPV4_ALEN, ip);
        case AF_INET6:
            return mnl_attr_put(nlh, type, IPV6_ALEN, ip);
    }
}

static int mnl_attr_parse_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    tb[mnl_attr_get_type(attr)] = attr;

    //printf("%hu\n", mnl_attr_get_type(attr));

    return MNL_CB_OK;
}

static int send_dump_request_cb(const struct nlmsghdr *nlh, void *data) {
    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR)
        return MNL_CB_ERROR;

    if (nlh->nlmsg_type == NLMSG_DONE)
        return MNL_CB_STOP;

    /*if (!(nlh->nlmsg_flags & NLM_F_DUMP_FILTERED))
        return MNL_CB_OK;*/

    struct dump_cb *cb = data;
    return (*cb->func)(nlh, cb->data);
}

static int send_request(struct netlink_handle* netlink_h) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)netlink_h->nl_buffer;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = netlink_h->nl_seq++;

    // Send the request
    if (mnl_socket_sendto(netlink_h->nl_socket, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink request: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(netlink_h->nl_socket, netlink_h->nl_buffer, netlink_h->nl_buffer_size);
    if (nbytes < 0) {
        bpfw_error("\nError receiving netlink response: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
        return -err->error;
    }

    return 0;
}

static int send_dump_request(struct netlink_handle *netlink_h, mnl_cb_t cb_func, void *cb_data) {
    unsigned int seq = netlink_h->nl_seq++;
    unsigned int portid = mnl_socket_get_portid(netlink_h->nl_socket);

    struct nlmsghdr *nlh = (struct nlmsghdr*)netlink_h->nl_buffer;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq;

    // Send the request
    if (mnl_socket_sendto(netlink_h->nl_socket, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink dump request: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(netlink_h->nl_socket, netlink_h->nl_buffer, netlink_h->nl_buffer_size);
    while (nbytes > 0) {
        struct dump_cb cb = { .func = cb_func, .data = cb_data };
        int rc = mnl_cb_run(netlink_h->nl_buffer, nbytes, seq, portid, send_dump_request_cb, &cb);

        if (rc == MNL_CB_ERROR) {
            struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
            bpfw_error("Netlink dump request error: %s (-%d).\n",
                strerror(-err->error), -err->error);

            return -1;
        }

        if (rc == MNL_CB_STOP)
            return 0;

        nbytes = mnl_socket_recvfrom(netlink_h->nl_socket, netlink_h->nl_buffer, netlink_h->nl_buffer_size);
    }

    if (nbytes < 0) {
        bpfw_error("\nError receiving netlink dump response: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    return 0;
}

static int get_ppp_peer_ipv6_cb(const struct nlmsghdr *nlh, void *peer_ip6) {
    struct nlattr *ifa[IFA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(struct ifaddrmsg), mnl_attr_parse_cb, ifa);

    if (ifa[IFA_ADDRESS])
        *(void**)peer_ip6 = mnl_attr_get_payload(ifa[IFA_ADDRESS]);

    return MNL_CB_OK;
}

static int get_ppp_peer_ipv6(struct netlink_handle* netlink_h, __u32 ifindex, void **peer_ip6) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETADDR;

    struct ifaddrmsg *ifaddrm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
    ifaddrm->ifa_family = AF_INET6;
    ifaddrm->ifa_index = ifindex;

    // Send request and receive response
    return send_dump_request(netlink_h, get_ppp_peer_ipv6_cb, (void*)peer_ip6);
}

static int get_neigh(struct netlink_handle* netlink_h, __u32 ifindex, struct flow_key_value* flow, __u8 dest_ip[IPV6_ALEN]) {
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
    if (rc < 0)
        return -1;

    if (rc != 0) {
        bpfw_warn_ip_on_if("Couldn't retrieve MAC address of ",
            dest_ip, flow->key.family, ifindex, rc);

        return 1;
    }

    if (!(ndm->ndm_state & NUD_VALID)) {
        bpfw_debug_ip("\nCurrently unreachable: ", dest_ip, flow->key.family, 0);
        bpfw_verbose("NUD state: 0x%02x\n", ndm->ndm_state);

        return 1;
    }

    struct nlattr *attr[NDA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ndm), mnl_attr_parse_cb, attr);

    if (!attr[NDA_LLADDR]) {
        bpfw_warn_ip_on_if(STRINGIFY(RTM_GETNEIGH)" didn't return MAC address of ",
            dest_ip, flow->key.family, ifindex, 0);

        return 1;
    }

    void *dest_mac = mnl_attr_get_payload(attr[NDA_LLADDR]);
    memcpy(flow->value.next_h.dest_mac, dest_mac, ETH_ALEN);

    return 0;
}

static int parse_bridge_if(struct netlink_handle* netlink_h, __u32 ifindex, struct flow_key_value *flow, __u8 dest_ip[IPV6_ALEN]) {
    int rc = get_neigh(netlink_h, ifindex, flow, dest_ip);
    if (rc < 0)
        return -1;

    if (rc != 0) {
        flow->value.action = ACTION_PASS;
        return 0;
    }

    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family = PF_BRIDGE;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put(nlh, NDA_LLADDR, ETH_ALEN, flow->value.next_h.dest_mac);
    mnl_attr_put_u32(nlh, NDA_MASTER, ifindex);

    // Send request and receive response
    rc = send_request(netlink_h);
    if (rc < 0)
        return -1;

    if (rc != 0) {
        if (rc == ENOENT)
            bpfw_debug_ip("\nCurrently unreachable: ", dest_ip, flow->key.family, 0);
        else
            bpfw_warn_ip_on_if("Couldn't retrieve bridge port of ",
                dest_ip, flow->key.family, ifindex, rc);

        flow->value.action = ACTION_PASS;
    }
    else
        flow->value.next_h.ifindex = ndm->ndm_ifindex;

    return 0;
}

static int parse_dsa_if(struct netlink_handle* netlink_h, struct nlattr **ifla, struct next_hop *next_h) {
    const char *port_name = mnl_attr_get_str(ifla[IFLA_PHYS_PORT_NAME]);
    __u8 dsa_port = strtoul(port_name + 1, NULL, 10);
    next_h->dsa_port = dsa_port | DSA_PORT_SET;

    __u32 dsa_switch = mnl_attr_get_u32(ifla[IFLA_LINK]);
    next_h->ifindex = dsa_switch;

    return 0;
}

static int parse_ppp_if(struct netlink_handle* netlink_h, __u32 ifindex, struct flow_value *f_value) {
    if (ifindex == netlink_h->pppoe.ifindex)
        goto fill_flow_value;

    void *peer_ip6 = NULL;

    int rc = get_ppp_peer_ipv6(netlink_h, ifindex, &peer_ip6);
    if (rc < 0)
        return -1;

    if (rc != 0 || !peer_ip6) {
        bpfw_warn_if("Couldn't retrieve IPv6 peer address of ", ifindex, rc);
        f_value->action = ACTION_PASS;

        return 0;
    }

    rc = get_pppoe_device(&netlink_h->pppoe, peer_ip6);
    if (rc < 0)
        return -1;

    if (rc != 0) {
        bpfw_verbose("Not a PPPoE interface?\n");
        f_value->action = ACTION_PASS;

        return 0;
    }

fill_flow_value:
    f_value->next_h.ifindex = netlink_h->pppoe.device;
    f_value->next_h.pppoe_id = netlink_h->pppoe.id;
    memcpy(f_value->next_h.dest_mac, netlink_h->pppoe.address, ETH_ALEN);

    return 0;
}

static int parse_vlan_if(struct netlink_handle* netlink_h, struct nlattr **ifla, struct nlattr **ifla_info, struct flow_value *f_value) {
    if (f_value->next_h.vlan_id) {
        f_value->action = ACTION_PASS;
        return 0;
    }

    struct nlattr *ifla_vlan[IFLA_VLAN_MAX + 1] = {};
    mnl_attr_parse_nested(ifla_info[IFLA_INFO_DATA], mnl_attr_parse_cb, ifla_vlan);

    __u16 vlan_proto = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_PROTOCOL]);
    if (vlan_proto != htons(ETH_P_8021Q)) {
        f_value->action = ACTION_PASS;
        return 0;
    }

    __u16 vlan_id = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_ID]);
    f_value->next_h.vlan_id = vlan_id;

    __u32 lower = mnl_attr_get_u32(ifla[IFLA_LINK]);
    f_value->next_h.ifindex = lower;

    return 0;
}

static int get_link(struct netlink_handle* netlink_h, __u32 ifindex, struct flow_key_value *flow, __u8 dest_ip[IPV6_ALEN], bool dsa) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        bpfw_error_if("Error retrieving link information for ", ifindex, rc);
        return -1;
    }

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    switch (ifinfom->ifi_type) {
        case ARPHRD_ETHER:
            break;

        case ARPHRD_PPP:
            bpfw_verbose("-> %s (ppp) ", mnl_attr_get_str(ifla[IFLA_IFNAME]));
            rc = parse_ppp_if(netlink_h, ifindex, &flow->value);

            goto out;

        default:
            bpfw_debug("Interface type: %hu\n", ifinfom->ifi_type);
            flow->value.action = ACTION_PASS;

            return 0;
    }

    if (mac_not_set(flow->value.next_h.src_mac)) {
        if (!ifla[IFLA_ADDRESS]) {
            bpfw_error(STRINGIFY(RTM_GETLINK)" didn't return MAC address of %s.\n",
                mnl_attr_get_str(ifla[IFLA_IFNAME]));

            return -1;
        }

        void *if_mac = mnl_attr_get_payload(ifla[IFLA_ADDRESS]);
        memcpy(flow->value.next_h.src_mac, if_mac, ETH_ALEN);
    }

    if (ifla[IFLA_LINKINFO]) {
        struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
        mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

        if (ifla_info[IFLA_INFO_KIND]) {
            const char *if_type = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);
            bpfw_verbose("-> %s (%s) ", mnl_attr_get_str(ifla[IFLA_IFNAME]), if_type);

            if (strcmp(if_type, "bridge") == 0) {
                rc = parse_bridge_if(netlink_h, ifindex, flow, dest_ip);
                goto out;
            }

            else if (strcmp(if_type, "vlan") == 0)
                rc = parse_vlan_if(netlink_h, ifla, ifla_info, &flow->value);

            else if (strcmp(if_type, "dsa") == 0 && dsa)
                rc = parse_dsa_if(netlink_h, ifla, &flow->value.next_h);
        }
    }

    if (mac_not_set(flow->value.next_h.dest_mac)) {
        rc = get_neigh(netlink_h, ifindex, flow, dest_ip);
        if (rc < 0)
            return -1;

        if (rc != 0) {
            flow->value.action = ACTION_PASS;
            return 0;
        }
    }

out:
    if (flow->value.next_h.ifindex != ifindex)
        rc = get_link(netlink_h, flow->value.next_h.ifindex, flow, dest_ip, dsa);

    return rc;
}

static int get_route(struct netlink_handle* netlink_h, struct flow_key_value* flow, __u8 dest_ip[IPV6_ALEN]) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETROUTE;

    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = flow->key.family;
    rtm->rtm_src_len = rtm->rtm_dst_len = flow->key.family == AF_INET ? 32 : 128;

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
    if (rc < 0)
        return -1;

    if (rc != 0) {
        bpfw_warn_ip("Couldn't retrieve route for ",
            flow->key.dest_ip, flow->key.family, rc);

        flow->value.action = ACTION_PASS;
        return 0;
    }

    bpfw_verbose_route_type("Rtt: ", rtm->rtm_type);

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
        bpfw_error_ip(STRINGIFY(RTM_GETROUTE)" didn't return output ifindex for ",
            flow->key.dest_ip, flow->key.family, 0);

        return -1;
    }

    flow->value.next_h.ifindex = mnl_attr_get_u32(attr[RTA_OIF]);
    flow->value.action = ACTION_REDIRECT;

    if (attr[RTA_GATEWAY]) {
        void *gateway = mnl_attr_get_payload(attr[RTA_GATEWAY]);
        ipcpy(dest_ip, gateway, flow->key.family);
    }

    return 0;
}

int netlink_get_next_hop(struct netlink_handle* netlink_h, struct flow_key_value* flow, bool dsa) {
    __u8 dest_ip[IPV6_ALEN];

    ipcpy(dest_ip, flow->value.n_entry.rewrite_flag & REWRITE_DEST_IP ?
        flow->value.n_entry.dest_ip : flow->key.dest_ip, flow->key.family);

    int rc = get_route(netlink_h, flow, dest_ip);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    rc = get_link(netlink_h, flow->value.next_h.ifindex, flow, dest_ip, dsa);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    bpfw_verbose_next_hop("-> ", &flow->value.next_h);

    return 0;
}

int netlink_ifindex_should_attach(struct netlink_handle *netlink_h, __u32 ifindex, bool dsa) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        bpfw_error_if("Error retrieving link information for ", ifindex, rc);
        return -1;
    }

    if (ifinfom->ifi_type != ARPHRD_ETHER)
        return 0;

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    if (ifla[IFLA_LINKINFO]) {
        struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
        mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

        if (ifla_info[IFLA_INFO_KIND]) {
            if (dsa)
                return 0;

            const char *if_type = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);
            if (strcmp(if_type, "dsa") == 0)
                return 1;

            return 0;
        }
    }

    return 1;
}

struct netlink_handle* netlink_init() {
    size_t nl_buffer_size = MNL_SOCKET_BUFFER_SIZE;

    struct netlink_handle *netlink_h = malloc(sizeof(struct netlink_handle) + nl_buffer_size);
    if (!netlink_h) {
        bpfw_error("Error allocating netlink handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    netlink_h->nl_buffer_size = nl_buffer_size;
    netlink_h->nl_seq = 0;
    netlink_h->pppoe.ifindex = 0;

    // Open a Netlink socket
    netlink_h->nl_socket = mnl_socket_open(NETLINK_ROUTE);
    if (!netlink_h->nl_socket) {
        bpfw_error("Error opening netlink socket: %s (-%d).\n", strerror(errno), errno);
        goto free;
    }

    netlink_set_strict_check(netlink_h, true);

    // Bind the socket
    if (mnl_socket_bind(netlink_h->nl_socket, 0, MNL_SOCKET_AUTOPID) != 0) {
        bpfw_error("Error binding netlink socket: %s (-%d).\n", strerror(errno), errno);
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
