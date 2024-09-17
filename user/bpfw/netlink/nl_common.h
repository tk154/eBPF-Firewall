#ifndef BPFW_NL_COMMON_H
#define BPFW_NL_COMMON_H

#include <linux/types.h>
#include <libmnl/libmnl.h>

#include "netlink.h"
#include "interfaces/pppoe.h"


struct nl_sock_buf {
    struct mnl_socket *sock;
    void *buf;

    unsigned int seq;
    size_t buf_size;
};

struct netlink_handle {
    struct nl_sock_buf req;
    struct nl_sock_buf not;

    bool dsa;
    __u32 dsa_switch;

    struct pppoe pppoe;
};


int mnl_attr_parse_cb(const struct nlattr *attr, void *data);
void mnl_attr_put_ip(struct nlmsghdr *nlh, __u16 type, void *ip, __u8 family);

int send_request(struct netlink_handle* nl_h);
int request_interface(struct netlink_handle* nl_h, __u32 ifindex);

int get_pppoe_device(struct netlink_handle* nl_h, __u32 ifindex, struct pppoe *pppoe);


#endif
