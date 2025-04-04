#include "nl_common.h"

#include <errno.h>
#include <stdlib.h>

#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>
#include <net/if_arp.h>

#include "../log/log.h"

#define NUD_VALID (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE | NUD_DELAY)


static bool mac_not_set(__u8 *mac) {
    return !mac[0] && !mac[1] && !mac[2]
        && !mac[3] && !mac[4] && !mac[5];
}

static int get_neigh(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value* flow, __be32 *dest_ip) {
    const struct nlattr *nda[NDA_MAX + 1] = {};
    DECLARE_ATTR_TB(nda);

    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family  = flow->key.family;
    ndm->ndm_ifindex = ifindex;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put_ip(nlh, NDA_DST, dest_ip, flow->key.family);

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

            return ACTION_NONE;
    }

    if (!(ndm->ndm_state & NUD_VALID)) {
        bpfw_debug_ip("\nCurrently unreachable: ", dest_ip, flow->key.family, 0);
        bpfw_verbose("NUD state: 0x%02x\n", ndm->ndm_state);

        return ACTION_NONE;
    }

    parse_attr(nlh, sizeof(*ndm), &nda_tb);

    if (!nda[NDA_LLADDR]) {
        bpfw_warn_ip_on_ifindex(STRINGIFY(RTM_GETNEIGH)" didn't return MAC address of ",
            dest_ip, flow->key.family, ifindex, 0);

        return ACTION_NONE;
    }

    void *dest_mac = mnl_attr_get_payload(nda[NDA_LLADDR]);
    memcpy(flow->value.next.hop.dest_mac, dest_mac, ETH_ALEN);

    return BPFW_RC_OK;
}


static int parse_bridge_if(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value *flow, __be32 *dest_ip) {
    int rc;

    if (mac_not_set(flow->value.next.hop.dest_mac)) {
        rc = get_neigh(nl_h, ifindex, flow, dest_ip);
        if (rc != BPFW_RC_OK)
            return rc;
    }

    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family = PF_BRIDGE;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put(nlh, NDA_LLADDR, ETH_ALEN, flow->value.next.hop.dest_mac);
    mnl_attr_put_u32(nlh, NDA_MASTER, ifindex);

    // Send request and receive response
    rc = send_request(nl_h);
    switch (rc) {
        case BPFW_RC_OK:
            flow->value.next.hop.ifindex = ndm->ndm_ifindex;

        case BPFW_RC_ERROR:
            return rc;
        
        case ENOENT:
            bpfw_debug_ip_on_ifindex("\nCurrently unreachable: ",
                dest_ip, flow->key.family, ifindex, 0);
                
            return ACTION_NONE;

        default:
            bpfw_warn_ip_on_ifindex("Couldn't retrieve bridge port of ",
                dest_ip, flow->key.family, ifindex, rc);

            return ACTION_NONE;
    }
}

static int parse_dsa_if(struct netlink_handle* nl_h, const struct nlattr **ifla, struct next_hop *hop) {
    const char *port_name = mnl_attr_get_str(ifla[IFLA_PHYS_PORT_NAME]);
    __u8 dsa_port = strtoul(port_name + 1, NULL, 10);
    hop->dsa_port = dsa_port | DSA_PORT_SET;

    __u32 dsa_switch = mnl_attr_get_u32(ifla[IFLA_LINK]);
    hop->ifindex = dsa_switch;

    return BPFW_RC_OK;
}

static int parse_vlan_if(struct netlink_handle* nl_h, const struct nlattr **ifla,
                         const struct nlattr **ifla_info, struct flow_value *f_value) {
    const struct nlattr *ifla_vlan[IFLA_VLAN_MAX + 1] = {};
    DECLARE_ATTR_TB(ifla_vlan);

    if (f_value->next.hop.vlan_id)
        return ACTION_NONE;

    parse_nested_attr(ifla_info[IFLA_INFO_DATA], &ifla_vlan_tb);

    __u16 vlan_proto = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_PROTOCOL]);
    if (vlan_proto != htons(ETH_P_8021Q))
        return ACTION_NONE;

    __u16 vlan_id = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_ID]);
    f_value->next.hop.vlan_id = vlan_id;

    __u32 lower = mnl_attr_get_u32(ifla[IFLA_LINK]);
    f_value->next.hop.ifindex = lower;

    return BPFW_RC_OK;
}

static int parse_ppp_if(struct netlink_handle* nl_h, __u32 ifindex,
                        const struct nlattr **ifla, struct flow_value *f_value) {
    const char *ifname = mnl_attr_get_str(ifla[IFLA_IFNAME]);
    bpfw_verbose("-> %s (ppp) ", ifname);

    if (ifindex != nl_h->pppoe.ifindex) {
        int rc = get_pppoe_device(nl_h, ifindex, &nl_h->pppoe);
        if (rc != BPFW_RC_OK)
            return rc;

        nl_h->pppoe.ifindex = ifindex;
    }

    f_value->next.hop.ifindex = nl_h->pppoe.device;
    f_value->next.hop.pppoe_id = nl_h->pppoe.id;
    memcpy(f_value->next.hop.dest_mac, nl_h->pppoe.address, ETH_ALEN);

    return BPFW_RC_OK;
}

static int parse_eth_if(struct netlink_handle* nl_h, __u32 ifindex, const struct nlattr **ifla,
                        struct flow_key_value *flow, __be32 *dest_ip) {
    const struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
    DECLARE_ATTR_TB(ifla_info);
    int rc = BPFW_RC_OK;

    if (mac_not_set(flow->value.next.hop.src_mac)) {
        if (!ifla[IFLA_ADDRESS]) {
            bpfw_error(STRINGIFY(RTM_GETLINK)" didn't return MAC address of %s.\n",
                mnl_attr_get_str(ifla[IFLA_IFNAME]));

            return BPFW_RC_ERROR;
        }

        void *if_mac = mnl_attr_get_payload(ifla[IFLA_ADDRESS]);
        memcpy(flow->value.next.hop.src_mac, if_mac, ETH_ALEN);
    }

    if (ifla[IFLA_LINKINFO]) {
        parse_nested_attr(ifla[IFLA_LINKINFO], &ifla_info_tb);

        if (ifla_info[IFLA_INFO_KIND]) {
            const char *ifname = mnl_attr_get_str(ifla[IFLA_IFNAME]);
            const char *if_type = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);

            bpfw_verbose("-> %s (%s) ", ifname, if_type);

            if (strcmp(if_type, "bridge") == 0)
                rc = parse_bridge_if(nl_h, ifindex, flow, dest_ip);

            else if (strcmp(if_type, "vlan") == 0)
                rc = parse_vlan_if(nl_h, ifla, ifla_info, &flow->value);

            else if (strcmp(if_type, "dsa") == 0)
                rc = nl_h->dsa ? parse_dsa_if(nl_h, ifla, &flow->value.next.hop) : BPFW_RC_OK;

            else
                rc = ACTION_NONE;
        }
    }

    if (rc == BPFW_RC_OK && mac_not_set(flow->value.next.hop.dest_mac))
        rc = get_neigh(nl_h, ifindex, flow, dest_ip);

    return rc;
}


static int get_link(struct netlink_handle* nl_h, __u32 ifindex, struct flow_key_value *flow, __be32 *dest_ip) {
    const struct nlattr *ifla[IFLA_MAX + 1] = {};
    DECLARE_ATTR_TB(ifla);

    int rc = request_interface(nl_h, ifindex);
    if (rc != BPFW_RC_OK)
        return rc;

    struct nlmsghdr *nlh = nl_h->req.buf;
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);

    parse_attr(nlh, sizeof(*ifinfom), &ifla_tb);

    switch (ifinfom->ifi_type) {
        case ARPHRD_ETHER:
            rc = parse_eth_if(nl_h, ifindex, ifla, flow, dest_ip);
            break;

        case ARPHRD_PPP:
            rc = parse_ppp_if(nl_h, ifindex, ifla, &flow->value);
            break;

        default:
            bpfw_debug("Interface type: %hu\n", ifinfom->ifi_type);
            return ACTION_NONE;
    }

    if (rc == BPFW_RC_OK && flow->value.next.hop.ifindex != ifindex)
        rc = get_link(nl_h, flow->value.next.hop.ifindex, flow, dest_ip);

    return rc;
}

static int get_route(struct netlink_handle* nl_h, struct flow_key_value* flow, __be32 *dest_ip) {
    const struct nlattr *rta[RTA_MAX + 1] = {};
    DECLARE_ATTR_TB(rta);

    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETROUTE;

    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = flow->key.family;
    rtm->rtm_src_len = rtm->rtm_dst_len = flow->key.family == AF_INET ? 32 : 128;

    // Add attributes
    //mnl_attr_put_u32(nlh, RTA_IIF, flow->value.next.iif);
    //mnl_attr_put_u8 (nlh, RTA_IP_PROTO, flow->key.proto);

    //mnl_attr_put_ip (nlh, RTA_SRC, flow->key.src_ip, flow->key.family);
    mnl_attr_put_ip (nlh, RTA_DST, flow->value.next.nat.rewrite_flag & REWRITE_DEST_IP ?
                                   flow->value.next.nat.dest_ip : flow->key.dest_ip, flow->key.family);

    /*mnl_attr_put_u16(nlh, RTA_SPORT, flow->key.src_port);
    mnl_attr_put_u16(nlh, RTA_DPORT, flow->value.next.nat.rewrite_flag & REWRITE_DEST_PORT ?
                                     flow->value.next.nat.dest_port : flow->key.dest_port);*/

    // Send request and receive response
    int rc = send_request(nl_h);
    __u8 rtm_type;

    switch (rc) {
        case BPFW_RC_OK:
            rtm_type = rtm->rtm_type;
            break;

        case BPFW_RC_ERROR:
            return BPFW_RC_ERROR;

        case EINVAL:
            rtm_type = RTN_BLACKHOLE;
            break;

        case EHOSTUNREACH:
            rtm_type = RTN_UNREACHABLE;
            break;

        case EACCES:
            rtm_type = RTN_PROHIBIT;
            break;

        default:
            bpfw_debug_ip("Couldn't retrieve route for ",
                flow->key.dest_ip, flow->key.family, rc);

            return ACTION_PASS;
    }

    bpfw_verbose_route_type("-> ", rtm_type);

    switch (rtm_type) {
        case RTN_UNICAST:
            break;

        case RTN_BLACKHOLE:
            return ACTION_DROP;

        default:
            return ACTION_PASS;
    }

    parse_attr(nlh, sizeof(*rtm), &rta_tb);

    if (!rta[RTA_OIF]) {
        bpfw_error_ip(STRINGIFY(RTM_GETROUTE)" didn't return output ifindex for ",
            flow->key.dest_ip, flow->key.family, 0);

        return BPFW_RC_ERROR;
    }

    __u32 oif = mnl_attr_get_u32(rta[RTA_OIF]);
    flow->value.next.hop.ifindex = oif;

    __u16 dest_attr = rta[RTA_GATEWAY] ? RTA_GATEWAY : RTA_DST;
    ipcpy(dest_ip, mnl_attr_get_payload(rta[dest_attr]), flow->key.family);

    return ACTION_FORWARD;
}

int netlink_get_next_hop(struct netlink_handle* nl_h, struct flow_key_value* flow) {
    __be32 dest_ip[4];

    int rc = get_route(nl_h, flow, dest_ip);
    if (rc != ACTION_FORWARD)
        return rc;

    rc = get_link(nl_h, flow->value.next.hop.ifindex, flow, dest_ip);
    if (rc != BPFW_RC_OK)
        return rc;

    bpfw_verbose_next_hop("-> ", &flow->value.next.hop);

    return ACTION_FORWARD;
}
