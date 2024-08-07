#ifndef BPFW_NETLINK_H
#define BPFW_NETLINK_H

#include "../common_user.h"


struct netlink_handle;

struct netlink_handle* netlink_init(bool auto_attach, bool dsa);
void netlink_destroy(struct netlink_handle* netlink_h);

int netlink_get_next_hop(struct netlink_handle* netlink_h, struct flow_key_value* flow);

int netlink_get_dsa(struct netlink_handle *netlink_h, __u32 *dsa_switch, char* dsa_proto);
int netlink_ifindex_should_attach(struct netlink_handle *netlink_h, __u32 ifindex);
int netlink_check_for_new_interfaces(struct netlink_handle *netlink_h, int (*cb_func)(__u32 ifindex, void *cb_data), void *cb_data);


#endif
