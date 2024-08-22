#include "nl_common.h"

#include <stdlib.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <linux/rtnetlink.h>

#include "../logging/logging.h"

#define INTERFACE_NOT_FOUND 1


struct dump_interface_cb {
    __u32 lower_ifindex;
    __u32 upper_ifindex;
    __u16 id;
};


static int dump_interface(struct netlink_handle *nl_h, const char *kind, mnl_cb_t cb_func, struct dump_interface_cb *cb_data) {
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfo = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));

    struct nlattr *ifla_info = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
    mnl_attr_put_str(nlh, IFLA_INFO_KIND, kind);
    mnl_attr_nest_end(nlh, ifla_info);

    return send_dump_request(nl_h, cb_func, cb_data);
}


static int check_if_bridge_slave(struct netlink_handle* nl_h, __u32 *ifindex) {
    int rc = request_interface(nl_h, *ifindex);
    if (rc != BPFW_RC_OK)
        return rc;

    struct nlmsghdr *nlh = nl_h->req.buf;
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    if (ifla[IFLA_LINKINFO]) {
        struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
        mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

        if (ifla_info[IFLA_INFO_SLAVE_KIND]) {
            const char *slave_kind = mnl_attr_get_str(ifla_info[IFLA_INFO_SLAVE_KIND]);

            if (strcmp(slave_kind, "bridge") == 0) {
                __u32 bridge_ifindex = mnl_attr_get_u32(ifla[IFLA_MASTER]);
                *ifindex = bridge_ifindex;

                char bridge_ifname[IF_NAMESIZE];
                if_indextoname(bridge_ifindex, bridge_ifname);
                bpfw_verbose("-> %s (bridge) ", bridge_ifname);

                return BPFW_RC_OK;
            }
        }
    }

    return INTERFACE_NOT_FOUND;
}

static int get_upper_interface(struct netlink_handle* nl_h, __u32 *ifindex, const char *kind, __u16 id, mnl_cb_t cb_func) {
    struct dump_interface_cb dump_data = { .lower_ifindex = *ifindex, .id = id, .upper_ifindex = 0 };

    int rc = dump_interface(nl_h, kind, cb_func, &dump_data);
    if (rc != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    if (!dump_data.upper_ifindex) {
        rc = check_if_bridge_slave(nl_h, ifindex);
        if (rc != BPFW_RC_OK)
            return rc;

        return get_upper_interface(nl_h, ifindex, kind, id, cb_func);
    }

    *ifindex = dump_data.upper_ifindex;

    return BPFW_RC_OK;
}


static int get_dsa_cb(const struct nlmsghdr *nlh, void *data) {
    struct dump_interface_cb *dump_data = data;
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    __u32 lower_ifindex = mnl_attr_get_u32(ifla[IFLA_LINK]);

    const char *port_name = mnl_attr_get_str(ifla[IFLA_PHYS_PORT_NAME]);
    __u8 dsa_port = strtoul(port_name + 1, NULL, 10);

    if (lower_ifindex == dump_data->lower_ifindex && dsa_port == dump_data->id) {
        const char *ifname = mnl_attr_get_str(ifla[IFLA_IFNAME]);
        bpfw_verbose("-> %s (dsa) ", ifname);

        dump_data->upper_ifindex = ifinfom->ifi_index;
    }

    return MNL_CB_OK;
}

static int dsa_get_upper(struct netlink_handle* nl_h, struct flow_key_value* flow) {
    return get_upper_interface(nl_h, &flow->value.next.iif, "dsa", flow->key.dsa_port & ~DSA_PORT_SET, get_dsa_cb);
}


static int get_vlan_cb(const struct nlmsghdr *nlh, void *data) {
    struct dump_interface_cb *dump_data = data;
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
    mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

    struct nlattr *ifla_vlan[IFLA_VLAN_MAX + 1] = {};
    mnl_attr_parse_nested(ifla_info[IFLA_INFO_DATA], mnl_attr_parse_cb, ifla_vlan);

    __u32 lower_ifindex = mnl_attr_get_u32(ifla[IFLA_LINK]);
    __u16 vlan_proto = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_PROTOCOL]);
    __u16 vlan_id = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_ID]);

    if (lower_ifindex == dump_data->lower_ifindex &&
        vlan_proto == htons(ETH_P_8021Q) && vlan_id == dump_data->id)
    {
        const char *ifname = mnl_attr_get_str(ifla[IFLA_IFNAME]);
        bpfw_verbose("-> %s (vlan) ", ifname);

        dump_data->upper_ifindex = ifinfom->ifi_index;
    }

    return MNL_CB_OK;
}

static int vlan_get_upper(struct netlink_handle *nl_h, struct flow_key_value* flow) {
    return get_upper_interface(nl_h, &flow->value.next.iif, "vlan", flow->key.vlan_id, get_vlan_cb);
}


static int check_pppoe_interface(struct netlink_handle *nl_h, __u32 ifindex) {
    int rc = request_interface(nl_h, ifindex);
    if (rc != BPFW_RC_OK)
        return rc;

    struct nlmsghdr *nlh = nl_h->req.buf;
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    const char *ifname = mnl_attr_get_str(ifla[IFLA_IFNAME]);

    if (ifinfom->ifi_type != ARPHRD_PPP) {
        bpfw_verbose("-> %s isn't a PPPoE interface.\n", ifname);
        return INTERFACE_NOT_FOUND;
    }

    bpfw_verbose("-> %s (ppp) ", ifname);

    return BPFW_RC_OK;
}

static int pppoe_get_upper(struct netlink_handle *nl_h, struct flow_key_value* flow) {
    struct pppoe *pppoe = &nl_h->pppoe;

    if (pppoe->id == flow->key.pppoe_id && pppoe->device == flow->value.next.iif &&
        memcmp(pppoe->address, flow->value.src_mac, ETH_ALEN) == 0)
    {
        if (check_pppoe_interface(nl_h, pppoe->ifindex) == BPFW_RC_OK) {
            flow->value.next.iif = pppoe->ifindex;
            return BPFW_RC_OK;
        }
    }
    else
        bpfw_verbose("-> Didn't retrieve PPPoE interface yet.\n");

    return INTERFACE_NOT_FOUND;
}


int get_input_interface(struct netlink_handle* nl_h, struct flow_key_value* flow) {
    int rc;
    flow->value.next.iif = flow->key.ifindex;

    if (flow->key.dsa_port) {
        rc = dsa_get_upper(nl_h, flow);
        if (rc != BPFW_RC_OK)
            return rc;
    }

    if (flow->key.vlan_id) {
        rc = vlan_get_upper(nl_h, flow);
        if (rc != BPFW_RC_OK)
            return rc;
    }

    if (flow->key.pppoe_id) {
        rc = pppoe_get_upper(nl_h, flow);
        if (rc != BPFW_RC_OK)
            return rc;
    }

    while ((rc = check_if_bridge_slave(nl_h, &flow->value.next.iif)) == BPFW_RC_OK);
    if (rc == BPFW_RC_ERROR)
        return BPFW_RC_ERROR;

    return BPFW_RC_OK;
}
