#include "nl_common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#include <net/if_arp.h>

#include "interfaces/dsa.h"
#include "../log/log.h"

#define NEW_INTERFACE   UINT32_MAX


struct dump_cb_data {
    mnl_cb_t func;
    void *data;
};

struct not_cb_data {
    struct netlink_handle *nl_h;
    
    struct netlink_cb link_cb;
    void *data;
};


static int open_socket_and_create_buffer(struct nl_sock_buf *nl, size_t buffer_size, unsigned int sock_groups) {
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

    nl->seq = 0;
    nl->buf_size = buffer_size;

    return BPFW_RC_OK;

socket_close:
    mnl_socket_close(nl->sock);

error:
    return BPFW_RC_ERROR;
}

static void close_socket_and_free_buffer(struct nl_sock_buf *nl) {
    // Close the socket
    mnl_socket_close(nl->sock);
    free(nl->buf);
}

static int socket_set_ext_ack(struct mnl_socket *socket, int enable) {
	if (setsockopt(mnl_socket_get_fd(socket), SOL_NETLINK,
            NETLINK_EXT_ACK, &enable, sizeof(enable)) != 0)
    {
        bpfw_error("Error setting netlink extended acknowledgment: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

static int socket_set_strict_check(struct mnl_socket *socket, int enable) {
	if (setsockopt(mnl_socket_get_fd(socket), SOL_NETLINK,
            NETLINK_GET_STRICT_CHK, &enable, sizeof(enable)) != 0)
    {
        bpfw_error("Error setting strict netlink checking: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

static int socket_set_blocking(struct mnl_socket *socket, bool block) {
    int sock_fd = mnl_socket_get_fd(socket);

    // Get the current flags
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags == -1) {
        bpfw_error("Error retrieving socket flags: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    flags = block ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);

    // Set the non-blocking flag
    if (fcntl(sock_fd, F_SETFL, flags) == -1) {
        bpfw_error("Error setting socket flags: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

void mnl_attr_put_ip(struct nlmsghdr *nlh, uint16_t type, const void *ip, __u8 family) {
    switch (family) {
        case AF_INET:
            return mnl_attr_put(nlh, type, sizeof(struct in_addr), ip);
        case AF_INET6:
            return mnl_attr_put(nlh, type, sizeof(struct in6_addr), ip);
    }
}

static int mnl_attr_parse_cb(const struct nlattr *attr, void *data) {
	const struct attr_tb *attr_tb = data;
	uint16_t type = mnl_attr_get_type(attr);

	if (type <= attr_tb->max_type)
		attr_tb->attr[type] = attr;

    return MNL_CB_OK;
}

static int mnl_attr_parse_cb_debug(const struct nlattr *attr, void *data) {
	const struct attr_tb *attr_tb = data;
	uint16_t type = mnl_attr_get_type(attr);

	if (type <= attr_tb->max_type)
		attr_tb->attr[type] = attr;

    bpfw_debug("%hu\n", type);

    return MNL_CB_OK;
}

int parse_attr(const struct nlmsghdr *nlh, unsigned int offset, struct attr_tb *tb) {
    return mnl_attr_parse(nlh, offset, mnl_attr_parse_cb, tb);
}

int parse_nested_attr(const struct nlattr *attr, struct attr_tb *tb) {
    return mnl_attr_parse_nested(attr, mnl_attr_parse_cb, tb);
}

static int process_ack(const struct nlmsghdr *nlhdr/*, size_t len*/) {
	const struct nlattr *err[NLMSGERR_ATTR_MAX + 1] = {};
    DECLARE_ATTR_TB(err);
	unsigned int err_offset = 0;
	unsigned int tlv_offset;
	struct nlmsgerr *nlerr;

	/*if ((len < NLMSG_HDRLEN + sizeof(*nlerr)) || (len < nlhdr->nlmsg_len))
		return -EFAULT;*/

	nlerr = mnl_nlmsg_get_payload(nlhdr);
	if (!(nlhdr->nlmsg_flags & NLM_F_ACK_TLVS))
		goto tlv_done;

	tlv_offset = sizeof(*nlerr);
	if (!(nlhdr->nlmsg_flags & NLM_F_CAPPED))
		tlv_offset += MNL_ALIGN(mnl_nlmsg_get_payload_len(&nlerr->msg));

	if (mnl_attr_parse(nlhdr, tlv_offset, mnl_attr_parse_cb, &err_tb) < 0)
		goto tlv_done;

	if (err[NLMSGERR_ATTR_MSG]) {
		const char *msg = mnl_attr_get_str(err[NLMSGERR_ATTR_MSG]);
        nlerr->error ?
            bpfw_error("Netlink error: %s.\n", msg):
            bpfw_warn("Netlink warning: %s.\n", msg);
	}
	if (err[NLMSGERR_ATTR_OFFS])
		err_offset = mnl_attr_get_u32(err[NLMSGERR_ATTR_OFFS]);

tlv_done:
	return -nlerr->error;
}

int send_request(struct netlink_handle* nl_h) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)nl_h->req.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = nl_h->req.seq++;

    // Send the request
    if (mnl_socket_sendto(nl_h->req.sock, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink request: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(nl_h->req.sock, nl_h->req.buf, nl_h->req.buf_size);
    if (nbytes < 0) {
        bpfw_error("\nError receiving netlink response: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }
    /*if (nbytes < NLMSG_HDRLEN) {
        bpfw_error("\nNetlink response is smaller then Netlink message header length (%u).\n",
            NLMSG_HDRLEN);
    }*/

    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR)
        return process_ack(nlh/*, nbytes*/);

    return BPFW_RC_OK;
}

static int send_dump_request_cb(const struct nlmsghdr *nlh, void *data) {
    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR)
        return process_ack(nlh);

    if (nlh->nlmsg_type == NLMSG_DONE)
        return MNL_CB_STOP;

    /*if (!(nlh->nlmsg_flags & NLM_F_DUMP_FILTERED))
        return MNL_CB_OK;*/

    struct dump_cb_data *cb = data;
    return (*cb->func)(nlh, cb->data);
}

static int send_dump_request(struct netlink_handle *nl_h, mnl_cb_t cb_func, void *cb_data) {
    struct dump_cb_data cb = { .func = cb_func, .data = cb_data };
    unsigned int portid = mnl_socket_get_portid(nl_h->req.sock);
    unsigned int seq = nl_h->req.seq++;
    struct nlmsghdr *nlh;
    ssize_t nbytes;
    int rc;

    nlh = (struct nlmsghdr*)nl_h->req.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq;

    // Send the request
    if (mnl_socket_sendto(nl_h->req.sock, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink dump request: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    // Receive and parse the response
    while ((nbytes = mnl_socket_recvfrom(nl_h->req.sock, nl_h->req.buf, nl_h->req.buf_size)) > 0) {
        rc = mnl_cb_run(nl_h->req.buf, nbytes, seq, portid, send_dump_request_cb, &cb);

        switch (rc) {
            case MNL_CB_ERROR:
                //printf("%d %s\n", errno, strerror(errno));
                return BPFW_RC_ERROR;
            case MNL_CB_STOP:
                return BPFW_RC_OK;
        }
    }

    if (nbytes < 0) {
        bpfw_error("\nError receiving netlink dump response: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int request_interface(struct netlink_handle* nl_h, __u32 ifindex) {
    // Prepare a Netlink request message
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nl_h->req.buf);
    nlh->nlmsg_type = RTM_GETLINK;

    struct ifinfomsg *ifinfom = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfom->ifi_index = ifindex;

    // Send request and receive response
    int rc = send_request(nl_h);
    switch (rc) {
        case BPFW_RC_OK:
        case BPFW_RC_ERROR:
            return rc;

        default:
            bpfw_error("Error querying ifindex %u: %s (-%d).\n",
                ifindex, strerror(rc), rc);

            return BPFW_RC_ERROR;
    }
}


static int get_ppp_peer_ipv6_cb(const struct nlmsghdr *nlh, void *peer_ip6) {
    const struct nlattr *ifa[IFA_MAX + 1] = {};
    DECLARE_ATTR_TB(ifa);

    mnl_attr_parse(nlh, sizeof(struct ifaddrmsg), mnl_attr_parse_cb, &ifa_tb);

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

int get_pppoe_device(struct netlink_handle* nl_h, __u32 ifindex, struct pppoe *pppoe) {
    void *peer_ip6 = NULL;

    int rc = get_ppp_peer_ipv6(nl_h, ifindex, &peer_ip6);
    if (rc == BPFW_RC_ERROR)
        return BPFW_RC_ERROR;

    if (!peer_ip6) {
        bpfw_verbose_ifindex("-> Couldn't retrieve IPv6 peer address of ", ifindex, 0);
        return ACTION_NONE;
    }

    rc = pppoe_get_device(peer_ip6, pppoe);
    switch (rc) {
        case BPFW_RC_OK:
        case BPFW_RC_ERROR:
            break;

        default:
            bpfw_verbose("Not a PPPoE interface?\n");
    }

    return rc;
}


static int get_dsa_cb(const struct nlmsghdr *nlh, void *dsa_switch) {
    const struct nlattr *ifla[IFLA_MAX + 1] = {};
    DECLARE_ATTR_TB(ifla);

    mnl_attr_parse(nlh, sizeof(struct ifinfomsg), mnl_attr_parse_cb, &ifla_tb);

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
        return BPFW_RC_ERROR;

    if (!nl_h->dsa)
        return BPFW_RC_OK;

    if (!nl_h->dsa_switch) {
        bpfw_error("Error: Couldn't find a DSA switch.\n");
        return BPFW_RC_ERROR;
    }

    *dsa_switch = nl_h->dsa_switch;

    return dsa_get_tag_proto(*dsa_switch, dsa_proto);
}

static int should_attach(struct netlink_handle *nl_h, const struct nlmsghdr *nlh) {
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);
    const struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
    const struct nlattr *ifla[IFLA_MAX + 1] = {};
    DECLARE_ATTR_TB(ifla_info);
    DECLARE_ATTR_TB(ifla);
    
    if (ifinfom->ifi_index == nl_h->dsa_switch)
        return nl_h->dsa;

    if (ifinfom->ifi_type != ARPHRD_ETHER)
        return NL_INTERFACE_DO_NOT_ATTACH;

    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, &ifla_tb);

    if (ifla[IFLA_LINKINFO]) {
        mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, &ifla_info_tb);

        if (ifla_info[IFLA_INFO_KIND]) {
            if (nl_h->dsa)
                return NL_INTERFACE_DO_NOT_ATTACH;

            const char *if_type = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);
            if (strcmp(if_type, "dsa") == 0)
                return NL_INTERFACE_DO_ATTACH;

            return NL_INTERFACE_DO_NOT_ATTACH;
        }
    }

    return NL_INTERFACE_DO_ATTACH;
}

int netlink_ifindex_should_attach(struct netlink_handle *nl_h, __u32 ifindex) {
    if (request_interface(nl_h, ifindex) != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    return should_attach(nl_h, nl_h->req.buf);
}


static int handle_newlink(const struct nlmsghdr *nlh, void *data) {
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);
    const struct nlattr *ifla[IFLA_MAX + 1] = {};
    DECLARE_ATTR_TB(ifla);
    struct not_cb_data *cb = data;

    if (ifinfom->ifi_change == NEW_INTERFACE) {
        mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, &ifla_tb);

        const char *ifname = mnl_attr_get_str(ifla[IFLA_IFNAME]);
        bpfw_debug("\nNew Interface: %s\n", ifname);

        if ((*cb->link_cb.newlink)(ifinfom->ifi_index, ifname, cb->data) != BPFW_RC_OK)
            return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

static int handle_dellink(const struct nlmsghdr *nlh, void *data) {
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);
    const struct nlattr *ifla[IFLA_MAX + 1] = {};
    DECLARE_ATTR_TB(ifla);
    struct not_cb_data *cb = data;

    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, &ifla_tb);

    const char *ifname = mnl_attr_get_str(ifla[IFLA_IFNAME]);
    bpfw_debug("\nInterface deleted: %s\n", ifname);

    if ((*cb->link_cb.dellink)(ifinfom->ifi_index, ifname, cb->data) != BPFW_RC_OK)
        return MNL_CB_ERROR;

    return MNL_CB_OK;
}

static int notification_cb(const struct nlmsghdr *nlh, void *data) {
    switch (nlh->nlmsg_type) {
        case RTM_NEWLINK:
            return handle_newlink(nlh, data);

        case RTM_DELLINK:
            return handle_dellink(nlh, data);

        default:
            bpfw_debug("Netlink notification message: %hu\n", nlh->nlmsg_type);
            return MNL_CB_OK;
    }
}

int netlink_check_notifications(struct netlink_handle *nl_h, struct netlink_cb link_cb, void *data) {
    struct not_cb_data cb = { .nl_h = nl_h, .link_cb = link_cb, .data = data };

    ssize_t nbytes;
    while ((nbytes = mnl_socket_recvfrom(nl_h->not.sock, nl_h->not.buf, nl_h->not.buf_size)) > 0) {
        int rc = mnl_cb_run(nl_h->not.buf, nbytes, 0, 0, notification_cb, &cb);
        if (rc == MNL_CB_ERROR) {
            bpfw_error("Error executing notification callback: %s (-%d).\n", strerror(errno), errno);
            return BPFW_RC_ERROR;
        }
    }

    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        bpfw_error("\nError receiving netlink notification: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


struct netlink_handle* netlink_init(bool auto_attach, bool dsa) {
    struct netlink_handle *nl_h = malloc(sizeof(struct netlink_handle));
    if (!nl_h) {
        bpfw_error("Error allocating netlink handle: %s (-%d).\n", strerror(errno), errno);
        goto error;
    }

    nl_h->dsa = dsa;
    nl_h->dsa_switch = 0;
    nl_h->pppoe.ifindex = 0;

    size_t buffer_size = MNL_SOCKET_BUFFER_SIZE;

    if (open_socket_and_create_buffer(&nl_h->req, buffer_size, 0) != 0)
        goto free;

    if (socket_set_ext_ack(nl_h->req.sock, true) != 0)
        goto close_req_socket;

    if (socket_set_strict_check(nl_h->req.sock, true) != 0)
        goto close_req_socket;

    unsigned int not_sock_groups = 0;
    if (auto_attach)
        not_sock_groups |= RTMGRP_LINK;

    if (open_socket_and_create_buffer(&nl_h->not, buffer_size, not_sock_groups) != 0)
        goto close_req_socket;

    if (socket_set_blocking(nl_h->not.sock, false) != 0)
        goto close_not_socket;

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
