#ifndef BPFW_NL_COMMON_H
#define BPFW_NL_COMMON_H

#include <linux/types.h>
#include <libmnl/libmnl.h>

#include "netlink.h"
#include "interfaces/pppoe.h"

#define DECLARE_ATTR_TB(attr) \
	struct attr_tb attr ## _tb = { (attr), (MNL_ARRAY_SIZE(attr) - 1) }


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

struct attr_tb {
	const struct nlattr **attr;
	unsigned int max_type;
};


void mnl_attr_put_ip(struct nlmsghdr *nlh, __u16 type, __be32 *ip, __u8 family);
int parse_attr(const struct nlmsghdr *nlh, unsigned int offset, struct attr_tb *tb);
int parse_nested_attr(const struct nlattr *attr, struct attr_tb *tb);

int send_request(struct netlink_handle* nl_h);
int request_interface(struct netlink_handle* nl_h, __u32 ifindex);

int get_pppoe_device(struct netlink_handle* nl_h, __u32 ifindex, struct pppoe *pppoe);


#endif
