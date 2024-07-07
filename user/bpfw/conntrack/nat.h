#ifndef BPFW_CONNTRACK_NAT_H
#define BPFW_CONNTRACK_NAT_H

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "../common_user.h"


/**
 * Check if the conntrack line contains NAT information, i.e., the connection has NAT
 * @param ct The conntrack object
 * @param flow The BPF flow key and value containing the NAT entries
 * **/
void check_nat(struct nf_conntrack *ct, struct flow_key_value *flow);


#endif
