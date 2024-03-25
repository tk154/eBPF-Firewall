#ifndef BPFW_CONNTRACK_H
#define BPFW_CONNTRACK_H

#include "../../common_user.h"


/**
 * Read conntrack info via libnetfilter_conntrack and save it into the BPF conntrack map.
 * Dynamically allocates memory, conntrack_destroy should be called when finished.
 * @param obj The BPF object containing the conntrack map
 * @returns On success 0, -1 if the map conntrack map couldn't be found inside the BPF object obj, and errno if the conntrack info couldn't be read
 * **/
int conntrack_init();


/**
 * Iterates to all entries of the BPF conntrack map and updates the conntrack info respectively
 * @param obj The BPF object containing the conntrack map
 * @returns On success 0, errno otherwise
 * **/
int conntrack_lookup(struct flow_key_value *flow);


/**
 * Frees dynamically allocated memory by libnetfilter_conntrack
**/
void conntrack_destroy();


#endif
