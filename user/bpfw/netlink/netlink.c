#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>

#include "netlink.h"
#include "dsa/dsa.h"
#include "pppoe/pppoe.h"

#define NUD_VALID (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE | NUD_DELAY)


struct nl_sock_buf {
    struct mnl_socket *sock;
    void *buf;
};

struct netlink_handle {
    struct nl_sock_buf req;
    struct nl_sock_buf not;

    __u32 seq;
    size_t buffer_size;

    bool dsa;
    __u32 dsa_switch;

    struct pppoe_device pppoe;
};

struct dump_cb {
    mnl_cb_t func;
    void *data;
};

struct notification_cb {
    struct netlink_handle *nl_h;
    
    int (*func)(__u32 ifindex, void* data);
    void *data;
};


static bool mac_not_set(__u8 *mac) {
    return !mac[0] && !mac[1] && !mac[2]
        && !mac[3] && !mac[4] && !mac[5];
}

static int socket_set_strict_check(struct mnl_socket *socket, int enable) {
	if (setsockopt(mnl_socket_get_fd(socket), SOL_NETLINK,
            NETLINK_GET_STRICT_CHK, &enable, sizeof(enable)) != 0)
    {
        bpfw_error("Error setting strict netlink checking: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    return 0;
}

int socket_set_blocking(struct mnl_socket *socket, bool block) {
    int sock_fd = mnl_socket_get_fd(socket);

    // Get the current flags
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags == -1) {
        bpfw_error("Error retrieving socket flags: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    flags = block ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);

    // Set the non-blocking flag
    if (fcntl(sock_fd, F_SETFL, flags) == -1) {
        bpfw_error("Error setting socket flags: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    return 0;
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

static int send_request(struct netlink_handle* nl_h) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)nl_h->req.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = nl_h->seq++;

    // Send the request
    if (mnl_socket_sendto(nl_h->req.sock, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink request: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(nl_h->req.sock, nl_h->req.buf, nl_h->buffer_size);
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

static int send_dump_request(struct netlink_handle *nl_h, mnl_cb_t cb_func, void *cb_data) {
    unsigned int seq = nl_h->seq++;
    unsigned int portid = mnl_socket_get_portid(nl_h->req.sock);

    struct nlmsghdr *nlh = (struct nlmsghdr*)nl_h->req.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq;

    // Send the request
    if (mnl_socket_sendto(nl_h->req.sock, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink dump request: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    // Receive and parse the response
    ssize_t nbytes;
    while ((nbytes = mnl_socket_recvfrom(nl_h->req.sock, nl_h->req.buf, nl_h->buffer_size)) > 0) {
        struct dump_cb cb = { .func = cb_func, .data = cb_data };
        int rc = mnl_cb_run(nl_h->req.buf, nbytes, seq, portid, send_dump_request_cb, &cb);

        if (rc == MNL_CB_ERROR) {
            struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
            bpfw_error("Netlink dump request error: %s (-%d).\n",
                strerror(-err->error), -err->error);

            return -1;
        }

        if (rc == MNL_CB_STOP)
            return 0;
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

static int get_ppp_peer_ipv6(struct netlink_handle* nl_h, __u32 ifindex, void **peer_ip6) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETADDR;

    struct ifaddrmsg *ifaddrm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
    ifaddrm->ifa_family = AF_INET6;
    ifaddrm->ifa_index  = ifindex;

    // Send request and receive response
    return send_dump_request(nl_h, get_ppp_peer_ipv6_cb, (void*)peer_ip6);
}

static int get_neigh(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value* flow, __u8 dest_ip[IPV6_ALEN]) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family  = flow->key.family;
    ndm->ndm_ifindex = ifindex;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put_ip(nlh, RTA_DST, dest_ip, flow->key.family);

    // Send request and receive response
    int rc = send_request(nl_h);
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

static int parse_bridge_if(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value *flow, __u8 dest_ip[IPV6_ALEN]) {
    int rc = get_neigh(nl_h, ifindex, flow, dest_ip);
    if (rc < 0)
        return -1;

    if (rc != 0) {
        flow->value.action = ACTION_PASS;
        return 0;
    }

    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family = PF_BRIDGE;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put(nlh, NDA_LLADDR, ETH_ALEN, flow->value.next_h.dest_mac);
    mnl_attr_put_u32(nlh, NDA_MASTER, ifindex);

    // Send request and receive response
    rc = send_request(nl_h);
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

static int parse_dsa_if(struct netlink_handle* nl_h, struct nlattr **ifla, struct next_hop *next_h) {
    const char *port_name = mnl_attr_get_str(ifla[IFLA_PHYS_PORT_NAME]);
    __u8 dsa_port = strtoul(port_name + 1, NULL, 10);
    next_h->dsa_port = dsa_port | DSA_PORT_SET;

    __u32 dsa_switch = mnl_attr_get_u32(ifla[IFLA_LINK]);
    next_h->ifindex = dsa_switch;

    return 0;
}

static int parse_ppp_if(struct netlink_handle* nl_h, __u32 ifindex, struct flow_value *f_value) {
    if (ifindex == nl_h->pppoe.ifindex)
        goto fill_flow_value;

    void *peer_ip6 = NULL;

    int rc = get_ppp_peer_ipv6(nl_h, ifindex, &peer_ip6);
    if (rc < 0)
        return -1;

    if (rc != 0 || !peer_ip6) {
        bpfw_warn_if("Couldn't retrieve IPv6 peer address of ", ifindex, rc);
        f_value->action = ACTION_PASS;

        return 0;
    }

    rc = get_pppoe_device(&nl_h->pppoe, peer_ip6);
    if (rc < 0)
        return -1;

    if (rc != 0) {
        bpfw_verbose("Not a PPPoE interface?\n");
        f_value->action = ACTION_PASS;

        return 0;
    }

fill_flow_value:
    f_value->next_h.ifindex = nl_h->pppoe.device;
    f_value->next_h.pppoe_id = nl_h->pppoe.id;
    memcpy(f_value->next_h.dest_mac, nl_h->pppoe.address, ETH_ALEN);

    return 0;
}

static int parse_vlan_if(struct netlink_handle* nl_h, struct nlattr **ifla, struct nlattr **ifla_info, struct flow_value *f_value) {
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

static int request_interface(struct netlink_handle* nl_h, __u32 ifindex) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request(nl_h);
    if (rc != 0) {
        bpfw_error_if("Error retrieving link information for ", ifindex, rc);
        return -1;
    }

    return 0;
}

static int get_link(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value *flow, void *dest_ip) {
    int rc = 0;

    if (request_interface(nl_h, ifindex) != 0)
        return -1;

    struct nlmsghdr *nlh = nl_h->req.buf;
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    switch (ifinfom->ifi_type) {
        case ARPHRD_ETHER:
            break;

        case ARPHRD_PPP:
            bpfw_verbose("-> %s (ppp) ", mnl_attr_get_str(ifla[IFLA_IFNAME]));
            rc = parse_ppp_if(nl_h, ifindex, &flow->value);

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
                rc = parse_bridge_if(nl_h, ifindex, flow, dest_ip);
                goto out;
            }

            else if (strcmp(if_type, "vlan") == 0)
                rc = parse_vlan_if(nl_h, ifla, ifla_info, &flow->value);

            else if (strcmp(if_type, "dsa") == 0 && nl_h->dsa)
                rc = parse_dsa_if(nl_h, ifla, &flow->value.next_h);
        }
    }

    if (mac_not_set(flow->value.next_h.dest_mac)) {
        rc = get_neigh(nl_h, ifindex, flow, dest_ip);
        if (rc < 0)
            return -1;

        if (rc != 0) {
            flow->value.action = ACTION_PASS;
            return 0;
        }
    }

out:
    if (flow->value.next_h.ifindex != ifindex)
        rc = get_link(nl_h, flow->value.next_h.ifindex, flow, dest_ip);

    return rc;
}

static int get_route(struct netlink_handle* nl_h, struct flow_key_value* flow, __u8 dest_ip[IPV6_ALEN]) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
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
    int rc = send_request(nl_h);
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

int netlink_get_next_hop(struct netlink_handle* nl_h, struct flow_key_value* flow) {
    __u8 dest_ip[IPV6_ALEN];

    ipcpy(dest_ip, flow->value.n_entry.rewrite_flag & REWRITE_DEST_IP ?
        flow->value.n_entry.dest_ip : flow->key.dest_ip, flow->key.family);

    int rc = get_route(nl_h, flow, dest_ip);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    rc = get_link(nl_h, flow->value.next_h.ifindex, flow, dest_ip);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    bpfw_verbose_next_hop("-> ", &flow->value.next_h);

    return 0;
}

static int get_dsa_cb(const struct nlmsghdr *nlh, void *dsa_switch) {
    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(struct ifinfomsg), mnl_attr_parse_cb, ifla);

    if (ifla[IFLA_LINK])
        *(__u32*)dsa_switch = mnl_attr_get_u32(ifla[IFLA_LINK]);

    return MNL_CB_OK;
}

int netlink_get_dsa(struct netlink_handle *nl_h, __u32 *dsa_switch, char* dsa_proto) {
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfo = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));

    struct nlattr *ifla_info = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
    mnl_attr_put_str(nlh, IFLA_INFO_KIND, "dsa");
    mnl_attr_nest_end(nlh, ifla_info);

    int rc = send_dump_request(nl_h, get_dsa_cb, &nl_h->dsa_switch);
    if (rc != 0)
        return -1;

    if (!nl_h->dsa)
        return 0;

    if (!nl_h->dsa_switch) {
        bpfw_error("Error: Couldn't find a DSA switch.\n");
        return -1;
    }

    *dsa_switch = nl_h->dsa_switch;

    return dsa_get_tag_proto(*dsa_switch, dsa_proto);
}

static bool should_attach(struct netlink_handle *nl_h, const struct nlmsghdr *nlh) {
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);
    
    if (ifinfom->ifi_index == nl_h->dsa_switch)
        return nl_h->dsa;

    if (ifinfom->ifi_type != ARPHRD_ETHER)
        return false;

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    if (ifla[IFLA_LINKINFO]) {
        struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
        mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

        if (ifla_info[IFLA_INFO_KIND]) {
            if (nl_h->dsa)
                return false;

            const char *if_type = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);
            if (strcmp(if_type, "dsa") == 0)
                return true;

            return false;
        }
    }

    return true;
}

int netlink_ifindex_should_attach(struct netlink_handle *nl_h, __u32 ifindex) {
    if (request_interface(nl_h, ifindex) != 0)
        return -1;

    return should_attach(nl_h, nl_h->req.buf);
}

static int notification_cb(const struct nlmsghdr *nlh, void *data) {
    struct notification_cb *cb = data;

    if (nlh->nlmsg_type != RTM_NEWLINK)
        goto out;

    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);
    if (ifinfom->ifi_change == UINT32_MAX && should_attach(cb->nl_h, nlh)) {
        struct nlattr *ifla[IFLA_MAX + 1] = {};
        mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);
        bpfw_debug("\nNew interface: %s\n", mnl_attr_get_str(ifla[IFLA_IFNAME]));

        if ((*cb->func)(ifinfom->ifi_index, cb->data) != 0)
            return MNL_CB_ERROR;
    }

out:
    return MNL_CB_OK;
}

int netlink_check_for_new_interfaces(struct netlink_handle *nl_h, int (*cb_func)(__u32 ifindex, void *cb_data), void *cb_data) {
    struct notification_cb cb = { .nl_h = nl_h, .func = cb_func, .data = cb_data };

    ssize_t nbytes;
    while ((nbytes = mnl_socket_recvfrom(nl_h->not.sock, nl_h->not.buf, nl_h->buffer_size)) > 0) {
        int rc = mnl_cb_run(nl_h->not.buf, nbytes, 0, 0, notification_cb, &cb);
        if (rc == MNL_CB_ERROR)
            return -1;
    }

    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        bpfw_error("\nError receiving netlink notification: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    return 0;
}

static int open_socket_and_create_buffer(struct nl_sock_buf *nl, unsigned int sock_groups, size_t buffer_size) {
    // Open a Netlink socket
    nl->sock = mnl_socket_open(NETLINK_ROUTE);
    if (!nl->sock) {
        bpfw_error("Error opening netlink socket: %s (-%d).\n", strerror(errno), errno);
        goto error;
    }

    // Bind the socket
    if (mnl_socket_bind(nl->sock, sock_groups, MNL_SOCKET_AUTOPID) != 0) {
        bpfw_error("Error binding netlink socket: %s (-%d).\n", strerror(errno), errno);
        goto socket_close;
    }

    nl->buf = malloc(buffer_size);
    if (!nl->buf) {
        bpfw_error("Error allocating netlink buffer: %s (-%d).\n", strerror(errno), errno);
        goto socket_close;
    }

    return 0;

socket_close:
    mnl_socket_close(nl->sock);

error:
    return -1;
}

static void close_socket_and_free_buffer(struct nl_sock_buf *nl) {
    // Close the socket
    mnl_socket_close(nl->sock);
    free(nl->buf);
}

struct netlink_handle* netlink_init(bool auto_attach, bool dsa) {
    struct netlink_handle *nl_h = malloc(sizeof(struct netlink_handle));
    if (!nl_h) {
        bpfw_error("Error allocating netlink handle: %s (-%d).\n", strerror(errno), errno);
        goto error;
    }

    nl_h->seq = 0;
    nl_h->buffer_size = MNL_SOCKET_BUFFER_SIZE;
    nl_h->dsa = dsa;
    nl_h->dsa_switch = 0;
    nl_h->pppoe.ifindex = 0;

    if (open_socket_and_create_buffer(&nl_h->req, 0, nl_h->buffer_size) != 0)
        goto free;

    if (socket_set_strict_check(nl_h->req.sock, true) != 0)
        goto close_req_socket;

    if (auto_attach) {
        if (open_socket_and_create_buffer(&nl_h->not, RTMGRP_LINK, nl_h->buffer_size) != 0)
            goto close_req_socket;

        if (socket_set_blocking(nl_h->not.sock, false) != 0)
            goto close_not_socket;
    }

    return nl_h;

close_not_socket:
    close_socket_and_free_buffer(&nl_h->not);

close_req_socket:
    close_socket_and_free_buffer(&nl_h->req);

free:
    free(nl_h);

error:
    return NULL;
}

void netlink_destroy(struct netlink_handle* nl_h) {
    close_socket_and_free_buffer(&nl_h->req);
    close_socket_and_free_buffer(&nl_h->not);

    free(nl_h);
}
