#include "nl_common.h"

#include <errno.h>
#include <stdlib.h>

#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>
#include <net/if_arp.h>

#include "../logging/logging.h"

#define NUD_VALID (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE | NUD_DELAY)
#define NO_NEXT_HOP 1


static bool mac_not_set(__u8 *mac) {
    return !mac[0] && !mac[1] && !mac[2]
        && !mac[3] && !mac[4] && !mac[5];
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

    *peer_ip6 = NULL;

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
    switch (rc) {
        case BPFW_RC_OK:
            break;

        case BPFW_RC_ERROR:
            return BPFW_RC_ERROR;

        default:
            bpfw_warn_ip_on_ifindex("Couldn't retrieve MAC address of ",
                dest_ip, flow->key.family, ifindex, rc);

            return NO_NEXT_HOP;
    }

    if (!(ndm->ndm_state & NUD_VALID)) {
        bpfw_debug_ip("\nCurrently unreachable: ", dest_ip, flow->key.family, 0);
        bpfw_verbose("NUD state: 0x%02x\n", ndm->ndm_state);

        return NO_NEXT_HOP;
    }

    struct nlattr *attr[NDA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ndm), mnl_attr_parse_cb, attr);

    if (!attr[NDA_LLADDR]) {
        bpfw_warn_ip_on_ifindex(STRINGIFY(RTM_GETNEIGH)" didn't return MAC address of ",
            dest_ip, flow->key.family, ifindex, 0);

        return NO_NEXT_HOP;
    }

    void *dest_mac = mnl_attr_get_payload(attr[NDA_LLADDR]);
    memcpy(flow->value.next_h.dest_mac, dest_mac, ETH_ALEN);

    return BPFW_RC_OK;
}


static int parse_bridge_if(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value *flow, __u8 dest_ip[IPV6_ALEN]) {
    int rc = get_neigh(nl_h, ifindex, flow, dest_ip);
    if (rc != BPFW_RC_OK)
        return rc;

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
    switch (rc) {
        case BPFW_RC_OK:
            flow->value.next_h.ifindex = ndm->ndm_ifindex;

        case BPFW_RC_ERROR:
            return rc;
        
        case ENOENT:
            bpfw_debug_ip("\nCurrently unreachable: ", dest_ip, flow->key.family, 0);
            return NO_NEXT_HOP;

        default:
            bpfw_warn_ip_on_ifindex("Couldn't retrieve bridge port of ",
                dest_ip, flow->key.family, ifindex, rc);

            return NO_NEXT_HOP;
    }
}

static int parse_dsa_if(struct netlink_handle* nl_h, struct nlattr **ifla, struct next_hop *next_h) {
    const char *port_name = mnl_attr_get_str(ifla[IFLA_PHYS_PORT_NAME]);
    __u8 dsa_port = strtoul(port_name + 1, NULL, 10);
    next_h->dsa_port = dsa_port | DSA_PORT_SET;

    __u32 dsa_switch = mnl_attr_get_u32(ifla[IFLA_LINK]);
    next_h->ifindex = dsa_switch;

    return BPFW_RC_OK;
}

static int parse_vlan_if(struct netlink_handle* nl_h, struct nlattr **ifla, struct nlattr **ifla_info, struct flow_value *f_value) {
    if (f_value->next_h.vlan_id)
        return NO_NEXT_HOP;

    struct nlattr *ifla_vlan[IFLA_VLAN_MAX + 1] = {};
    mnl_attr_parse_nested(ifla_info[IFLA_INFO_DATA], mnl_attr_parse_cb, ifla_vlan);

    __u16 vlan_proto = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_PROTOCOL]);
    if (vlan_proto != htons(ETH_P_8021Q))
        return NO_NEXT_HOP;

    __u16 vlan_id = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_ID]);
    f_value->next_h.vlan_id = vlan_id;

    __u32 lower = mnl_attr_get_u32(ifla[IFLA_LINK]);
    f_value->next_h.ifindex = lower;

    return BPFW_RC_OK;
}

static int parse_ppp_if(struct netlink_handle* nl_h, __u32 ifindex, struct flow_value *f_value) {
    if (ifindex == nl_h->pppoe.ifindex)
        goto fill_flow_value;

    void *peer_ip6;
    int rc = get_ppp_peer_ipv6(nl_h, ifindex, &peer_ip6);
    if (rc == BPFW_RC_ERROR)
        return BPFW_RC_ERROR;

    if (!peer_ip6) {
        bpfw_verbose_ifindex("-> Couldn't retrieve IPv6 peer address of ", ifindex, "", 0);
        return NO_NEXT_HOP;
    }

    rc = pppoe_get_device(peer_ip6, &nl_h->pppoe);
    switch (rc) {
        case BPFW_RC_OK:
            nl_h->pppoe.ifindex = ifindex;
            break;
        
        case BPFW_RC_ERROR:
            return BPFW_RC_ERROR;

        default:
            bpfw_verbose("Not a PPPoE interface?\n");
            return NO_NEXT_HOP;
    }

fill_flow_value:
    f_value->next_h.ifindex = nl_h->pppoe.device;
    f_value->next_h.pppoe_id = nl_h->pppoe.id;
    memcpy(f_value->next_h.dest_mac, nl_h->pppoe.address, ETH_ALEN);

    return BPFW_RC_OK;
}


static int get_link(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value *flow, void *dest_ip) {
    int rc = request_interface(nl_h, ifindex);
    if (rc != BPFW_RC_OK)
        return BPFW_RC_ERROR;

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
            return NO_NEXT_HOP;
    }

    if (mac_not_set(flow->value.next_h.src_mac)) {
        if (!ifla[IFLA_ADDRESS]) {
            bpfw_error(STRINGIFY(RTM_GETLINK)" didn't return MAC address of %s.\n",
                mnl_attr_get_str(ifla[IFLA_IFNAME]));

            return BPFW_RC_ERROR;
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

    if (mac_not_set(flow->value.next_h.dest_mac))
        rc = get_neigh(nl_h, ifindex, flow, dest_ip);

out:
    if (rc != BPFW_RC_OK) {
        flow->value.action = ACTION_PASS;
        return rc;
    }

    if (flow->value.next_h.ifindex != ifindex)
        rc = get_link(nl_h, flow->value.next_h.ifindex, flow, dest_ip);

    return rc;
}

static int get_route(struct netlink_handle* nl_h, struct flow_key_value* flow, __u32 iif, __u8 dest_ip[IPV6_ALEN]) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETROUTE;

    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = flow->key.family;
    rtm->rtm_src_len = rtm->rtm_dst_len = flow->key.family == AF_INET ? 32 : 128;

    // Add attributes
    mnl_attr_put_u32(nlh, RTA_IIF, iif);
    mnl_attr_put_u8 (nlh, RTA_IP_PROTO, flow->key.proto);
    mnl_attr_put_ip (nlh, RTA_SRC, flow->key.src_ip, flow->key.family);
    mnl_attr_put_ip (nlh, RTA_DST, dest_ip, flow->key.family);
    mnl_attr_put_u16(nlh, RTA_SPORT, flow->key.src_port);
    mnl_attr_put_u16(nlh, RTA_DPORT, flow->value.n_entry.rewrite_flag & REWRITE_DEST_PORT ?
                                     flow->value.n_entry.dest_port : flow->key.dest_port);

    // Send request and receive response
    int rc = send_request(nl_h);
    switch (rc) {
        case BPFW_RC_OK:
            break;

        case BPFW_RC_ERROR:
            return BPFW_RC_ERROR;

        default:
            bpfw_warn_ip("Couldn't retrieve route for ",
                flow->key.dest_ip, flow->key.family, rc);

            return NO_NEXT_HOP;
    }

    bpfw_verbose_route_type("Rtt: ", rtm->rtm_type);

    switch (rtm->rtm_type) {
        case RTN_UNICAST:
            break;

        case RTN_BLACKHOLE:
            flow->value.action = ACTION_DROP;
            return BPFW_RC_OK;

        default:
            flow->value.action = ACTION_PASS;
            return BPFW_RC_OK;
    }

    struct nlattr *attr[RTA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*rtm), mnl_attr_parse_cb, attr);

    if (!attr[RTA_OIF]) {
        bpfw_error_ip(STRINGIFY(RTM_GETROUTE)" didn't return output ifindex for ",
            flow->key.dest_ip, flow->key.family, 0);

        return BPFW_RC_ERROR;
    }

    flow->value.next_h.ifindex = mnl_attr_get_u32(attr[RTA_OIF]);
    flow->value.action = ACTION_REDIRECT;

    if (attr[RTA_GATEWAY]) {
        void *gateway = mnl_attr_get_payload(attr[RTA_GATEWAY]);
        ipcpy(dest_ip, gateway, flow->key.family);
    }

    return BPFW_RC_OK;
}

int netlink_get_next_hop(struct netlink_handle* nl_h, struct flow_key_value* flow) {
    __u32 iif = flow->key.ifindex;

    int rc = get_input_interface(nl_h, &flow->key, &iif);
    if (rc != BPFW_RC_OK) {
        flow->value.action = ACTION_PASS;
        return rc;
    }

    __u8 dest_ip[IPV6_ALEN];
    ipcpy(dest_ip, flow->value.n_entry.rewrite_flag & REWRITE_DEST_IP ?
        flow->value.n_entry.dest_ip : flow->key.dest_ip, flow->key.family);

    rc = get_route(nl_h, flow, iif, dest_ip);
    if (rc != BPFW_RC_OK || flow->value.action != ACTION_REDIRECT)
        return rc;

    rc = get_link(nl_h, flow->value.next_h.ifindex, flow, dest_ip);
    if (rc != BPFW_RC_OK)
        return rc;

    bpfw_verbose_next_hop("-> ", &flow->value.next_h);

    return BPFW_RC_OK;
}

int netlink_get_route(struct netlink_handle* nl_h, struct flow_key_value* flow, __u32 *iif) {
    bpfw_debug_key("\nNon: ", &flow->key);

    int rc = get_input_interface(nl_h, &flow->key, iif);
    if (rc != BPFW_RC_OK) {
        flow->value.action = ACTION_PASS;
        return rc;
    }

    __u8 dest_ip[IPV6_ALEN];
    ipcpy(dest_ip, flow->value.n_entry.rewrite_flag & REWRITE_DEST_IP ?
        flow->value.n_entry.dest_ip : flow->key.dest_ip, flow->key.family);

    rc = get_route(nl_h, flow, *iif, dest_ip);
    if (rc != BPFW_RC_OK || flow->value.action != ACTION_REDIRECT)
        return rc;

    bpfw_verbose_ifindex("-> ", flow->value.next_h.ifindex, "", 0);

    return BPFW_RC_OK;
}
