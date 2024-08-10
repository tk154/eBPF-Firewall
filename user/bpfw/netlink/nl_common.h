#ifndef BPFW_NL_COMMON_H
#define BPFW_NL_COMMON_H

#include <linux/types.h>
#include <libmnl/libmnl.h>

#include "netlink.h"
#include "pppoe/pppoe.h"


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

    struct pppoe pppoe;
};


int mnl_attr_parse_cb(const struct nlattr *attr, void *data);
void mnl_attr_put_ip(struct nlmsghdr *nlh, __u16 type, void *ip, __u8 family);

int send_request(struct netlink_handle* nl_h);
int send_dump_request(struct netlink_handle *nl_h, mnl_cb_t cb_func, void *cb_data);

int request_interface(struct netlink_handle* nl_h, __u32 ifindex);
int get_input_interface(struct netlink_handle* nl_h, struct flow_key* f_key, __u32 *iif);


#endif
