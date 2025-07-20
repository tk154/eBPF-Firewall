#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "bpf.h"
#include "../log/log.h"


struct tc_opts {
    __u32 handle;
    __u32 priority;
};

struct bpf_interface {
    enum bpf_hook hook;
    struct tc_opts tc;
};

// Struct to keep BPF object and program pointers together
struct bpf_handle {
    /* BPF object pointers */
    struct bpf_object *obj;
    struct bpf_program *rss_prog;

    struct map *ifaces;
    enum bpf_hook hook;
    
    /* BPF program file descriptors */
    int xdp_prog_fd;
    int tc_prog_fd;
    //int rss_prog_fd;

    bool obj_loaded;
};


#endif
