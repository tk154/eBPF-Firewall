#ifndef BPFW_NETLINK_H
#define BPFW_NETLINK_H

#include "../common_user.h"


enum {
    NL_INTERFACE_DO_NOT_ATTACH,
    NL_INTERFACE_DO_ATTACH
};

typedef int (*newlink_cb_t) (__u32 ifindex, void *cb_data);


struct netlink_handle;

struct netlink_handle* netlink_init(bool auto_attach, bool dsa);
void netlink_destroy(struct netlink_handle* netlink_h);

int netlink_get_next_hop(struct netlink_handle* netlink_h, struct flow_key_value* flow);
int netlink_get_route(struct netlink_handle* nl_h, struct flow_key_value* flow);

int netlink_get_dsa(struct netlink_handle *netlink_h, __u32 *dsa_switch, char* dsa_proto);
int netlink_ifindex_should_attach(struct netlink_handle *netlink_h, __u32 ifindex);
int netlink_check_notifications(struct netlink_handle *netlink_h, newlink_cb_t newlink, void *data);


#endif
