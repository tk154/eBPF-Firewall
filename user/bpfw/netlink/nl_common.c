#include "nl_common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#include <net/if_arp.h>

#include "interfaces/dsa.h"
#include "../logging/logging.h"

#define NEW_INTERFACE UINT32_MAX
#define INTERFACE_NOT_FOUND 1


struct dump_cb_data {
    mnl_cb_t func;
    void *data;
};

struct not_cb_data {
    struct netlink_handle *nl_h;
    
    newlink_cb_t newlink_cb;
    void *data;
};


static int socket_set_strict_check(struct mnl_socket *socket, int enable) {
	if (setsockopt(mnl_socket_get_fd(socket), SOL_NETLINK,
            NETLINK_GET_STRICT_CHK, &enable, sizeof(enable)) != 0)
    {
        bpfw_error("Error setting strict netlink checking: %s (-%d).\n", strerror(errno), errno);
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

void mnl_attr_put_ip(struct nlmsghdr *nlh, uint16_t type, void *ip, __u8 family) {
    switch (family) {
        case AF_INET:
            return mnl_attr_put(nlh, type, IPV4_ALEN, ip);
        case AF_INET6:
            return mnl_attr_put(nlh, type, IPV6_ALEN, ip);
    }
}

int mnl_attr_parse_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    tb[mnl_attr_get_type(attr)] = attr;

    return MNL_CB_OK;
}

int mnl_attr_parse_cb_debug(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    tb[mnl_attr_get_type(attr)] = attr;

    bpfw_debug("%hu\n", mnl_attr_get_type(attr));

    return MNL_CB_OK;
}

int send_request(struct netlink_handle* nl_h) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)nl_h->req.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = nl_h->seq++;

    // Send the request
    if (mnl_socket_sendto(nl_h->req.sock, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink request: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    // Receive and parse the response
    ssize_t nbytes = mnl_socket_recvfrom(nl_h->req.sock, nl_h->req.buf, nl_h->buffer_size);
    if (nbytes < 0) {
        bpfw_error("\nError receiving netlink response: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
        return -err->error;
    }

    return BPFW_RC_OK;
}

static int send_dump_request_cb(const struct nlmsghdr *nlh, void *data) {
    // If there was an error
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
        bpfw_error("Netlink dump request error: %s (-%d).\n",
            strerror(-err->error), -err->error);

        return MNL_CB_ERROR;
    }

    if (nlh->nlmsg_type == NLMSG_DONE)
        return MNL_CB_STOP;

    /*if (!(nlh->nlmsg_flags & NLM_F_DUMP_FILTERED))
        return MNL_CB_OK;*/

    struct dump_cb_data *cb = data;
    return (*cb->func)(nlh, cb->data);
}

int send_dump_request(struct netlink_handle *nl_h, mnl_cb_t cb_func, void *cb_data) {
    unsigned int seq = nl_h->seq++;
    unsigned int portid = mnl_socket_get_portid(nl_h->req.sock);

    struct nlmsghdr *nlh = (struct nlmsghdr*)nl_h->req.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq;

    // Send the request
    if (mnl_socket_sendto(nl_h->req.sock, nlh, nlh->nlmsg_len) < 0) {
        bpfw_error("\nError sending netlink dump request: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    // Receive and parse the response
    ssize_t nbytes;
    while ((nbytes = mnl_socket_recvfrom(nl_h->req.sock, nl_h->req.buf, nl_h->buffer_size)) > 0) {
        struct dump_cb_data cb = { .func = cb_func, .data = cb_data };
        int rc = mnl_cb_run(nl_h->req.buf, nbytes, seq, portid, send_dump_request_cb, &cb);

        switch (rc) {
            case MNL_CB_ERROR:
                return BPFW_RC_ERROR;
            case MNL_CB_STOP:
                return BPFW_RC_OK;
        }
    }

    if (nbytes < 0) {
        bpfw_error("\nError receiving netlink dump response: %s (-%d).\n", strerror(errno), errno);
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

        case ENODEV:
            bpfw_debug("Device with ifindex %u is gone.\n", ifindex);
            return INTERFACE_NOT_FOUND;

        default:
            bpfw_error_ifindex("Error retrieving link information for ", ifindex, "", rc);
            return BPFW_RC_ERROR;
    }
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
    
    if (ifinfom->ifi_index == nl_h->dsa_switch)
        return nl_h->dsa;

    if (ifinfom->ifi_type != ARPHRD_ETHER)
        return NL_INTERFACE_DO_NOT_ATTACH;

    struct nlattr *ifla[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

    if (ifla[IFLA_LINKINFO]) {
        struct nlattr *ifla_info[IFLA_INFO_MAX + 1] = {};
        mnl_attr_parse_nested(ifla[IFLA_LINKINFO], mnl_attr_parse_cb, ifla_info);

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
    struct not_cb_data *cb = data;
    struct ifinfomsg *ifinfom = mnl_nlmsg_get_payload(nlh);

    if (ifinfom->ifi_change == NEW_INTERFACE && should_attach(cb->nl_h, nlh)) {
        struct nlattr *ifla[IFLA_MAX + 1] = {};
        mnl_attr_parse(nlh, sizeof(*ifinfom), mnl_attr_parse_cb, ifla);

        bpfw_debug("\nNew interface: %s\n", mnl_attr_get_str(ifla[IFLA_IFNAME]));

        if ((*cb->newlink_cb)(ifinfom->ifi_index, cb->data) != BPFW_RC_OK)
            return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

static int notification_cb(const struct nlmsghdr *nlh, void *data) {
    switch (nlh->nlmsg_type) {
        case RTM_NEWLINK:
            return handle_newlink(nlh, data);

        case RTM_DELLINK:
            return MNL_CB_OK;

        default:
            bpfw_debug("Netlink notification message: %hu\n", nlh->nlmsg_type);
            return MNL_CB_OK;
    }
}

int netlink_check_notifications(struct netlink_handle *nl_h, newlink_cb_t newlink, void *data) {
    struct not_cb_data cb = { .nl_h = nl_h, .newlink_cb = newlink, .data = data };

    ssize_t nbytes;
    while ((nbytes = mnl_socket_recvfrom(nl_h->not.sock, nl_h->not.buf, nl_h->buffer_size)) > 0) {
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

    unsigned int not_sock_groups = 0;
    if (auto_attach)
        not_sock_groups |= RTMGRP_LINK;

    if (open_socket_and_create_buffer(&nl_h->not, not_sock_groups, nl_h->buffer_size) != 0)
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
