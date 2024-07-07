#ifndef BPFW_NETLINK_H
#define BPFW_NETLINK_H

#include "../common_user.h"


struct netlink_handle;

struct netlink_handle* netlink_init();
void netlink_destroy(struct netlink_handle* netlink_h);

int netlink_get_next_hop(struct netlink_handle* netlink_h, struct flow_key_value* flow, bool dsa);

int netlink_ifindex_should_attach(struct netlink_handle *netlink_h, __u32 ifindex, bool dsa);


#endif
