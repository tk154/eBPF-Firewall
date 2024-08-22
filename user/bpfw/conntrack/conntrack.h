#ifndef BPFW_CONNTRACK_H
#define BPFW_CONNTRACK_H

#include "../common_user.h"


struct conntrack_handle;

enum conntrack_conn_state {
    CT_CONN_NOT_FOUND,
    CT_CONN_NOT_ESTABLISHED,
    CT_CONN_ESTABLISHED
};


/**
 * Read conntrack info via libnetfilter_conntrack and save it into the BPF conntrack map.
 * Dynamically allocates memory, conntrack_destroy should be called when finished.
 * @param obj The BPF object containing the conntrack map
 * @returns On success 0, -1 if the map conntrack map couldn't be found inside the BPF object obj, and errno if the conntrack info couldn't be read
 * **/
struct conntrack_handle* conntrack_init();

/**
 * Iterates to all entries of the BPF conntrack map and updates the conntrack info respectively
 * @param obj The BPF object containing the conntrack map
 * @returns On success 0, errno otherwise
 * **/
int conntrack_do_lookup(struct conntrack_handle* conntrack_h, struct flow_key_value *flow);
void conntrack_check_nat(struct conntrack_handle* conntrack_h, struct flow_key_value *flow);
int conntrack_update_timeout(struct conntrack_handle* conntrack_h);
void conntrack_free_ct_entry(struct conntrack_handle* conntrack_h);

/**
 * Frees dynamically allocated memory by libnetfilter_conntrack
**/
void conntrack_destroy(struct conntrack_handle* conntrack_h);


#endif
