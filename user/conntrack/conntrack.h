#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <bpf/libbpf.h>


/**
 * Read conntrack info from '/proc/net/nf_conntrack' and save it into the BPF conntrack map
 * @param obj The BPF object containing the conntrack map
 * @returns On success 0, -1 if the map conntrack map couldn't be found inside the BPF object obj, and errno if the conntrack file couldn't be opened
 * **/
int read_and_save_conntrack(struct bpf_object* obj);

#endif
