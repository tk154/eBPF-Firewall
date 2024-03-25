#ifndef BPFW_NETLINK_H
#define BPFW_NETLINK_H

#include "../common_user.h"


int netlink_init();
void netlink_destroy();

int netlink_get_next_hop(struct flow_key_value* flow);


#endif
