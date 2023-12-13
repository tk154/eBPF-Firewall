#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <bpf/libbpf.h>


/**
 * Read conntrack info via libnetfilter_conntrack and save it into the BPF conntrack map.
 * Dynamically allocates memory, conntrack_destroy should be called when finished.
 * @param obj The BPF object containing the conntrack map
 * @returns On success 0, -1 if the map conntrack map couldn't be found inside the BPF object obj, and errno if the conntrack info couldn't be read
 * **/
int conntrack_init(struct bpf_object* obj);


/**
 * Iterates to all entries of the BPF conntrack map and updates the conntrack info respectively
 * @param obj The BPF object containing the conntrack map
 * @returns On success 0, errno otherwise
 * **/
int update_conntrack(struct bpf_object* obj);


/**
 * Frees dynamically allocated memory by libnetfilter_conntrack
**/
void conntrack_destroy();


#endif
