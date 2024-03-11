#ifndef BPFW_CONNTRACK_NAT_H
#define BPFW_CONNTRACK_NAT_H

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "../../common.h"


/**
 * Check if the conntrack line contains NAT information, i.e., the connection has NAT
 * @param ct The conntrack object
 * @param f_key The BPF flow key
 * @param f_value The BPF flow value containing the NAT entries
 * **/
void check_nat(struct nf_conntrack *ct, struct flow_key *f_key, struct flow_value *f_value);


#endif
