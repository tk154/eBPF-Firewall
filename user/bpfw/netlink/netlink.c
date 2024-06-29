#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <libmnl/libmnl.h>

#include "../common_user.h"


struct netlink_handle {
    struct mnl_socket *nl_socket;
    size_t nl_buffer_size;
    __u32 nl_seq;

    // Flexible buffer for all Netlink requests and responses
    char nl_buffer[];
};


static int get_link(struct netlink_handle *netlink_h, struct flow_key_value *flow, __u32 ifindex, void *dest_ip);

static void log_next_hop(struct next_hop *next_h) {
    if (fw_log_level < FW_LOG_LEVEL_VERBOSE)
        return;

    char ifname[IF_NAMESIZE];
    if_indextoname(next_h->ifindex, ifname);

    printf("-> %s", ifname);

    if (next_h->dsa_port & DSA_PORT_SET)
        printf("@p%hhu", next_h->dsa_port & ~DSA_PORT_SET);

    if (next_h->vlan_id)
        printf(" vlan=%hu", next_h->vlan_id);

    if (next_h->pppoe_id)
        printf(" pppoe=0x%hx", ntohs(next_h->pppoe_id));

    printf(" %02x:%02x:%02x:%02x:%02x:%02x"
                " %02x:%02x:%02x:%02x:%02x:%02x\n",
        next_h->src_mac[0], next_h->src_mac[1], next_h->src_mac[2],
        next_h->src_mac[3], next_h->src_mac[4], next_h->src_mac[5], 
        next_h->dest_mac[0], next_h->dest_mac[1], next_h->dest_mac[2],
        next_h->dest_mac[3], next_h->dest_mac[4], next_h->dest_mac[5]);
}


static bool mac_empty(__u8 *mac) {
    for (int i = 0; i < ETH_ALEN; i++)
        if (mac[i])
            return false;

    return true;
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

static int get_dsa_switch_cb(const struct nlmsghdr *nlh, void *dsa_switch) {
    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR)
        return MNL_CB_ERROR;

    if (nlh->nlmsg_type == NLMSG_DONE)
        return MNL_CB_STOP;

    if (!(nlh->nlmsg_flags & NLM_F_DUMP_FILTERED))
        return MNL_CB_OK;

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(struct ifinfomsg), mnl_attr_parse_cb, ifla);

    if (ifla[IFLA_LINK])
        *(__u32*)dsa_switch = mnl_attr_get_u32(ifla[IFLA_LINK]);

    return MNL_CB_OK;
}

static int send_request(struct netlink_handle* netlink_h) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)netlink_h->nl_buffer;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = netlink_h->nl_seq++;

    // Send the request
    if (mnl_socket_sendto(netlink_h->nl_socket, nlh, nlh->nlmsg_len) < 0) {
        FW_ERROR("\nError sending netlink request: %s (-%d).\n", strerror(errno), errno);
        return -errno;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(netlink_h->nl_socket, netlink_h->nl_buffer, netlink_h->nl_buffer_size);
    if (nbytes < 0) {
        FW_ERROR("\nError receiving netlink response: %s (-%d).\n", strerror(errno), errno);
        return -errno;
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
        FW_ERROR("\nError sending netlink request: %s (-%d).\n", strerror(errno), errno);
        return -errno;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(netlink_h->nl_socket, netlink_h->nl_buffer, netlink_h->nl_buffer_size);
    while (nbytes > 0) {
        int rc = mnl_cb_run(netlink_h->nl_buffer, nbytes, seq, portid, cb_func, cb_data);
        if (rc == MNL_CB_ERROR) {
            struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
            return -err->error;
        }

        if (rc == MNL_CB_STOP)
            break;

        nbytes = mnl_socket_recvfrom(netlink_h->nl_socket, netlink_h->nl_buffer, netlink_h->nl_buffer_size);
    }

    if (nbytes == -1) {
        FW_ERROR("\nError receiving netlink response: %s (-%d).\n", strerror(errno), errno);
        return -errno;
    }

    return 0;
}

static int request_interface(struct netlink_handle *netlink_h, __u32 ifindex) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);

        FW_ERROR("Error retrieving %s link information: %s (-%d).\n",
            ifname, strerror(rc), rc);

        return rc;
    }

    return 0;
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
    if (rc < 0)
        return rc;

    if (rc != 0) {
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(flow->key.family, flow->key.src_ip, dst_ip, sizeof(dst_ip));

        FW_WARN("Couldn't retrieve route for %s: %s (-%d).\n", dst_ip, strerror(rc), rc);

        flow->value.action = ACTION_PASS;
        return 0;
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
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(flow->key.family, flow->key.src_ip, dst_ip, sizeof(dst_ip));

        FW_ERROR("%s didn't return output ifindex for %s.\n",
            STRINGIFY(RTM_GETROUTE), dst_ip);

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
    if (rc < 0)
        return rc;

    if (rc != 0) {
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);

        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(flow->key.family, flow->key.src_ip, dst_ip, sizeof(dst_ip));

        FW_WARN("Couldn't retrieve MAC address of %s on %s: %s (-%d).\n",
            dst_ip, ifname, strerror(rc), rc);

        return rc;
    }

    struct nlattr *attr[NDA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ndm), mnl_attr_parse_cb, attr);

    if (!attr[NDA_LLADDR]) {
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);

        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(flow->key.family, flow->key.src_ip, dst_ip, sizeof(dst_ip));

        FW_ERROR("%s didn't return MAC address of %s on %s.\n",
            STRINGIFY(RTM_GETROUTE), dst_ip, ifname);

        return 1;
    }

    void *dest_mac = mnl_attr_get_payload(attr[NDA_LLADDR]);
    memcpy(flow->value.next_h.dest_mac, dest_mac, ETH_ALEN);

    return 0;
}

static int parse_bridge_if(struct netlink_handle* netlink_h, struct flow_key_value *flow, __u32 ifindex, void *dest_ip) {
    int rc = get_neigh(netlink_h, flow, ifindex, dest_ip);
    if (rc < 0)
        return rc;

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
        return rc;

    if (rc != 0) {
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);

        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(flow->key.family, flow->key.src_ip, dst_ip, sizeof(dst_ip));

        FW_WARN("Couldn't retrieve %s port for %s: %s (-%d).\n",
            ifname, dst_ip, strerror(rc), rc);

        flow->value.action = ACTION_PASS;
        return 0;
    }

    return get_link(netlink_h, flow, ndm->ndm_ifindex, dest_ip);
}

static int parse_dsa_if(struct netlink_handle* netlink_h, struct nlattr **ifla, struct flow_key_value *flow, void *dest_ip) {
    const char *port_name = mnl_attr_get_str(ifla[IFLA_PHYS_PORT_NAME]);
    __u8 dsa_port = strtoul(port_name + 1, NULL, 10);
    flow->value.next_h.dsa_port = dsa_port | DSA_PORT_SET;

    __u32 dsa_switch = mnl_attr_get_u32(ifla[IFLA_LINK]);
    return get_link(netlink_h, flow, dsa_switch, dest_ip);
}

static int parse_ppp_if(struct netlink_handle* netlink_h, struct flow_key_value *flow, void *dest_ip) {
    const char *pppoe_file_path = "/proc/net/pppoe";

    FILE *pppoe_file = fopen(pppoe_file_path, "r");
    if (!pppoe_file) {
        FW_ERROR("Error opening '%s': %s (-%d).\n", pppoe_file_path, strerror(errno), errno);
        return errno;
    }

    char pppoe_line[64];
    fgets(pppoe_line, sizeof(pppoe_line), pppoe_file);

    if (!fgets(pppoe_line, sizeof(pppoe_line), pppoe_file)) {
        FW_ERROR("Error reading '%s': %s (-%d).\n", pppoe_file_path, strerror(errno), errno);
        fclose(pppoe_file);

        return errno;
    }

    fclose(pppoe_file);

    const char *delim = " ";
    char *pppoe_str = strtok(pppoe_line, delim);

    __u32 session_id = strtoul(pppoe_str, NULL, 16);
    if (!session_id) {
        FW_ERROR("Error parsing session ID from '%s'\n", pppoe_file);
        return -1;
    }

    pppoe_str = strtok(NULL, delim);

    __u8 dest_mac[ETH_ALEN];
    if (sscanf(pppoe_str, "%02x:%02x:%02x:%02x:%02x:%02x",
        &dest_mac[0], &dest_mac[1], &dest_mac[2],
        &dest_mac[3], &dest_mac[4], &dest_mac[5]) != ETH_ALEN) {
            FW_ERROR("Error parsing destination MAC from '%s'\n", pppoe_file);
            return -1;
        }

    memcpy(flow->value.next_h.dest_mac, dest_mac, ETH_ALEN);

    pppoe_str = strtok(NULL, delim);
    pppoe_str[strcspn(pppoe_str, "\n")] = '\0';

    __u32 ifindex = if_nametoindex(pppoe_str);
    if (!ifindex) {
        FW_ERROR("Error parsing interface from '%s'\n", pppoe_file);
        return -1;
    }

    flow->value.next_h.pppoe_id = session_id;

    return get_link(netlink_h, flow, ifindex, dest_ip);
}

static int parse_vlan_if(struct netlink_handle* netlink_h, struct nlattr **ifla, struct nlattr **ifla_info, struct flow_key_value *flow, void *dest_ip) {
    if (flow->value.next_h.vlan_id) {
        flow->value.action = ACTION_PASS;
        return 0;
    }

    struct nlattr *ifla_vlan[IFLA_VLAN_MAX + 1] = {};
    mnl_attr_parse_nested(ifla_info[IFLA_INFO_DATA], mnl_attr_parse_cb, ifla_vlan);

    __u16 vlan_proto = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_PROTOCOL]);
    if (vlan_proto != htons(ETH_P_8021Q)) {
        flow->value.action = ACTION_PASS;
        return 0;
    }

    __u16 vlan_id = mnl_attr_get_u16(ifla_vlan[IFLA_VLAN_ID]);
    flow->value.next_h.vlan_id = vlan_id;

    __u32 ifindex = mnl_attr_get_u32(ifla[IFLA_LINK]);
    return get_link(netlink_h, flow, ifindex, dest_ip);
}

static int get_link(struct netlink_handle* netlink_h, struct flow_key_value *flow, __u32 ifindex, void *dest_ip) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request(netlink_h);
    if (rc != 0) {
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);

        FW_ERROR("Error retrieving %s link information: %s (-%d).\n",
            ifname, strerror(rc), rc);

        return rc;
    }

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    if (ifla[IFLA_LINKINFO]) {
        struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
        mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

        if (ifla_info[IFLA_INFO_KIND]) {
            const char *if_type = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);
            FW_VERBOSE("-> %s (%s) ", mnl_attr_get_str(ifla[IFLA_IFNAME]), if_type);

            if (strcmp(if_type, "bridge") == 0)
                return parse_bridge_if(netlink_h, flow, ifindex, dest_ip);

            if (strcmp(if_type, "ppp") == 0)
                return parse_ppp_if(netlink_h, flow, dest_ip);

            if (strcmp(if_type, "vlan") == 0)
                return parse_vlan_if(netlink_h, ifla, ifla_info, flow, dest_ip);

            if (strcmp(if_type, "dsa") == 0)
                if (flow->key.dsa_port)
                    return parse_dsa_if(netlink_h, ifla, flow, dest_ip);
        }
    }

    if (!ifla[IFLA_ADDRESS]) {
        FW_ERROR("%s didn't return %s MAC address.\n",
            STRINGIFY(RTM_GETLINK), mnl_attr_get_str(ifla[IFLA_IFNAME]));

        return -1;
    }

    void *if_mac = mnl_attr_get_payload(ifla[IFLA_ADDRESS]);
    memcpy(flow->value.next_h.src_mac, if_mac, ETH_ALEN);

    flow->value.next_h.ifindex = ifindex;

    return 0;
}

int netlink_get_next_hop(struct netlink_handle* netlink_h, struct flow_key_value* flow) {
    __u32 ifindex;
    __u8 dest_ip[flow->key.family == AF_INET ? IPV4_ALEN : IPV6_ALEN];

    ipcpy(dest_ip, flow->value.n_entry.rewrite_flag & REWRITE_DEST_IP ?
        flow->value.n_entry.dest_ip : flow->key.dest_ip, flow->key.family);

    int rc = get_route(netlink_h, flow, &ifindex, dest_ip);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    rc = get_link(netlink_h, flow, ifindex, dest_ip);
    if (rc != 0 || flow->value.action != ACTION_REDIRECT)
        return rc;

    if (mac_empty(flow->value.next_h.dest_mac)) {
        rc = get_neigh(netlink_h, flow, ifindex, dest_ip);
        if (rc != 0) {
            flow->value.action = ACTION_PASS;
            return 0;
        }
    }

    log_next_hop(&flow->value.next_h);

    return 0;
}

int netlink_get_route(struct netlink_handle *netlink_h, struct flow_key_value* flow) {
    __u8 dest_ip[flow->key.family == AF_INET ? 4 : 16];
    ipcpy(dest_ip, flow->key.dest_ip, flow->key.family);

    return get_route(netlink_h, flow, &flow->value.next_h.ifindex, dest_ip);
}

int netlink_if_should_attach(struct netlink_handle *netlink_h, __u32 ifindex, bool dsa) {
    int rc = request_interface(netlink_h, ifindex);
    if (rc != 0)
        return -rc;

    struct nlmsghdr *nlh = (struct nlmsghdr*)netlink_h->nl_buffer;
    struct ifinfomsg *ifinfo = mnl_nlmsg_get_payload(nlh);
    if (ifinfo->ifi_type == ARPHRD_LOOPBACK)
        return 0;

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfo), mnl_attr_parse_cb, ifla);

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

int netlink_get_dsa_switch(struct netlink_handle *netlink_h, __u32 *dsa_switch) {
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(netlink_h->nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfo = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));

    struct nlattr *ifla_info = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
    mnl_attr_put_str(nlh, IFLA_INFO_KIND, "dsa");
    mnl_attr_nest_end(nlh, ifla_info);

    return send_dump_request(netlink_h, get_dsa_switch_cb, dsa_switch);
}

struct netlink_handle* netlink_init() {
    size_t nl_buffer_size = MNL_SOCKET_BUFFER_SIZE;

    struct netlink_handle *netlink_h = malloc(sizeof(struct netlink_handle) + nl_buffer_size);
    if (!netlink_h) {
        FW_ERROR("Error allocating netlink handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    netlink_h->nl_buffer_size = nl_buffer_size;
    netlink_h->nl_seq = 0;

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
