#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "bpf.h"
#include "../log/log.h"


struct tc_opts {
    __u32 handle, priority;
};

// Struct to keep BPF object and program pointers together
struct bpf_handle {
    struct bpf_object *obj;         // BPF object pointer

    struct map *iface_hooks;
    struct map *tc_opts;
    enum bpf_hook hook;
    
    int xdp_prog_fd, tc_prog_fd;    // BPF program file descriptors
    bool obj_loaded;
};


#endif
