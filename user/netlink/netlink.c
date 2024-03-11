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


static inline void log_next_hop(struct next_hop *next_h) {
#if FW_LOG_LEVEL >= FW_LOG_LEVEL_DEBUG
    char src_mac[18], dest_mac[18];
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
        next_h->src_mac[0], next_h->src_mac[1], next_h->src_mac[2],
        next_h->src_mac[3], next_h->src_mac[4], next_h->src_mac[5]);
    snprintf(dest_mac, sizeof(dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
        next_h->dest_mac[0], next_h->dest_mac[1], next_h->dest_mac[2],
        next_h->dest_mac[3], next_h->dest_mac[4], next_h->dest_mac[5]);

    FW_DEBUG("%u %s %s\n", next_h->ifindex, src_mac, dest_mac);
#endif
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

static int get_route(struct flow_key *f_key, struct flow_value *f_value, __be32 *dest_ip) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_buffer);
    nlh->nlmsg_type = RTM_GETROUTE;

    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;

    // Add attributes
    mnl_attr_put_u32(nlh, RTA_IIF, f_key->ifindex);
    mnl_attr_put_u32(nlh, RTA_SRC, f_key->src_ip);
    mnl_attr_put_u32(nlh, RTA_DST, *dest_ip);
    mnl_attr_put_u16(nlh, RTA_SPORT, f_key->src_port);
    mnl_attr_put_u16(nlh, RTA_DPORT, f_value->n_entry.dest_port ?
                        f_value->n_entry.dest_port : f_key->dest_port);
    mnl_attr_put_u8(nlh, RTA_IP_PROTO, f_key->l4_proto);

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
            f_value->action = ACTION_DROP;
            return 0;

        case RTN_LOCAL:
            f_value->action = ACTION_PASS;
            return 0;

        default:
            FW_DEBUG("rtm_type: %u\n", rtm->rtm_type);
            f_value->action = ACTION_PASS;
            return 0;
    }

    __u32 ifindex = 0;
    struct nlattr *attr;

    mnl_attr_for_each(attr, nlh, sizeof(struct rtmsg)) {
        switch (mnl_attr_get_type(attr)) {
            // Output interface index
            case RTA_OIF:
                ifindex = mnl_attr_get_u32(attr);
            break;

            // If the packet cannot be send directly,
            // save the IP of the Gateway
            case RTA_GATEWAY:
                *dest_ip = mnl_attr_get_u32(attr);
            break;
        }
    }

    if (!ifindex) {
        FW_ERROR("Netlink didn't return output ifindex");
        return -1;
    }

    f_value->action = ACTION_REDIRECT;
    f_value->next_h.ifindex = ifindex;

    return 0;
}

static int get_if_mac(struct next_hop *next_h) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_buffer);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifi_req = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifi_req->ifi_index = next_h->ifindex;

    // Send request and receive response
    int rc = send_request();
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIZE(RTM_GETLINK));
        return rc;
    }

    struct nlattr *attr;
    mnl_attr_for_each(attr, nlh, sizeof(struct ifinfomsg)) {
        // Interface L2 address
        if (mnl_attr_get_type(attr) == IFLA_ADDRESS) {
            memcpy(next_h->src_mac, mnl_attr_get_payload(attr), sizeof(next_h->src_mac));
            return 0;
        }
    }

    FW_ERROR("Netlink didn't return interface MAC address");
    return -1;
}

static int get_dest_mac(struct next_hop *next_h, __be32 dest_ip) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_buffer);
    nlh->nlmsg_type = RTM_GETNEIGH;

    struct ndmsg *nd_req = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    nd_req->ndm_family = AF_INET;
    nd_req->ndm_ifindex = next_h->ifindex;

    // Set the destination IP (of Receiver or Gateway)
    mnl_attr_put_u32(nlh, NDA_DST, dest_ip);

    // Send request and receive response
    int rc = send_request();
    if (rc != 0) {
        FW_ERROR("%s request error.\n", STRINGIZE(RTM_GETNEIGH));
        return rc;
    }

    struct nlattr *attr;
    mnl_attr_for_each(attr, nlh, sizeof(struct ndmsg)) {
        // Neighbor cache link layer address
        if (mnl_attr_get_type(attr) == NDA_LLADDR) {
            memcpy(next_h->dest_mac, mnl_attr_get_payload(attr), sizeof(next_h->dest_mac));
            return 0;
        }
    }

    FW_ERROR("Netlink didn't return destination MAC address");
    return -1;
}

int get_next_hop(struct flow_key *f_key, struct flow_value *f_value) {
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

    nl_buffer = malloc(NL_BUFFER_SIZE);
    __be32 dest_ip = f_value->n_entry.dest_ip ?
        f_value->n_entry.dest_ip : f_key->dest_ip;

    int rc = get_route(f_key, f_value, &dest_ip);
    if (rc != 0 || f_value->action != ACTION_REDIRECT)
        goto free_buffer;

    rc = get_if_mac(&f_value->next_h);
    if (rc != 0)
        goto free_buffer;

    rc = get_dest_mac(&f_value->next_h, dest_ip);
    if (rc != 0)
        goto free_buffer;

    log_next_hop(&f_value->next_h);

free_buffer:
    free(nl_buffer);

    // Close the socket
    mnl_socket_close(nl_socket);

    return rc;
}
