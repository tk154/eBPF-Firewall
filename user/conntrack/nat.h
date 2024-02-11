#ifndef BPFW_CONNTRACK_NAT_H
#define BPFW_CONNTRACK_NAT_H

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "../../common.h"


/**
 * Check if the conntrack line contains NAT information, i.e., the connection has NAT
 * @param ct The conntrack object
 * @param c_key The BPF connection key
 * @param c_value The BPF connection value containing the NAT entries
 * **/
void check_nat(struct nf_conntrack *ct, struct conn_key *c_key, struct conn_value *c_value);


#endif
