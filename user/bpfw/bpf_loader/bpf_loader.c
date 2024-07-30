#include "bpf_loader.h"

#include <errno.h>
#include <glob.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>


// Struct to keep BPF object and program pointers together
struct bpf_handle {
    struct bpf_object  *obj;    // BPF object pointer
    struct bpf_program *prog;   // BPF program pointer

    enum bpfw_hook hook;

    bool  dsa;
    __u32 dsa_switch;

    //struct {
    //    __u32 handle;
    //    __u32 priority;
    //} tc;
};


#define SYSFS_SYS_CLASS_NET "/sys/class/net/"

static int get_dsa_switch(__u32 *dsa_switch, char *tag_proto) {
    const char *glob_path = SYSFS_SYS_CLASS_NET"*/dsa/tagging";
    int rc = 0;

    glob_t globbuf;
    glob(glob_path, 0, NULL, &globbuf);

    size_t sw_count = globbuf.gl_pathc;
    if (sw_count == 0)
        goto globfree;

    char* tag_file_path = globbuf.gl_pathv[0];
    FILE *tag_file = fopen(tag_file_path, "r");
    if (!tag_file) {
        bpfw_error("Error opening '%s': %s (-%d).\n", tag_file_path, strerror(errno), errno);
        rc = -1;

        goto globfree;
    }

    if (!fgets(tag_proto, DSA_PROTO_MAX_LEN, tag_file)) {
        bpfw_error("Error reading '%s': %s (-%d).\n", tag_file_path, strerror(errno), errno);
        rc = -1;

        goto fclose;
    }

    tag_proto[strcspn(tag_proto, "\n")] = '\0';

    char *sw_name = tag_file_path + sizeof(SYSFS_SYS_CLASS_NET) - 1;
    sw_name[strcspn(sw_name, "/")] = '\0';
    *dsa_switch = if_nametoindex(sw_name);

fclose:
    fclose(tag_file);

globfree:
    globfree(&globbuf);

    return rc;
}

static int check_dsa(struct bpf_handle *bpf, struct dsa_size *dsa_size) {
    bpf->dsa_switch = 0;
    char switch_proto[DSA_PROTO_MAX_LEN];

    if (get_dsa_switch(&bpf->dsa_switch, switch_proto) != 0)
        return -1;

    if (!bpf->dsa)
        return 0;

    if (!bpf->dsa_switch) {
        bpfw_error("Error: Couldn't find a DSA switch.\n");
        return -1;
    }

    size_t dsa_tag_sec_size;
    const struct dsa_tag *dsa_tag = bpf_get_section_data(bpf, DSA_RO_SECTION, &dsa_tag_sec_size);
    if (!dsa_tag)
        return -1;

    __s8 index = -1;
    for (int i = 0; i < dsa_tag_sec_size / sizeof(struct dsa_tag); i++) {
        if (strncmp(switch_proto, dsa_tag[i].proto, DSA_PROTO_MAX_LEN) == 0) {
            index = i;
            break;
        }
    }

    if (index == -1) {
        bpfw_error("Error: BPF program doesn't support the DSA tagging protocol '%s' of the DSA switch.\n",
            switch_proto);

        return -1;
    }

    *dsa_size = dsa_tag[index].size;

    struct dsa *dsa = bpf_get_section_data(bpf, DSA_BSS_SECTION, NULL);
    if (!dsa)
        return -1;

    dsa->ifindex = bpf->dsa_switch;
    dsa->proto   = index + 1;

    return 0;
}

static __u32 get_xdp_flag(enum bpfw_hook hook) {
    switch (hook) {
        case BPFW_HOOK_XDP_GENERIC:
            return XDP_FLAGS_SKB_MODE;
        case BPFW_HOOK_XDP_DRIVER:
            return XDP_FLAGS_DRV_MODE;
        case BPFW_HOOK_XDP_OFFLOAD:
            return XDP_FLAGS_HW_MODE;
        default:
            return 0;
    }
}


struct bpf_handle* bpf_load_program(const char *obj_path, enum bpfw_hook hook, bool dsa, struct dsa_size *dsa_size) {
    struct bpf_handle* bpf = (struct bpf_handle*)malloc(sizeof(struct bpf_handle));
    if (!bpf) {
        bpfw_error("Error allocating BPF handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    bpf->hook = hook;
    bpf->dsa  = dsa;

    const char *prog_name;
    enum bpf_prog_type prog_type;

    if (hook & BPFW_HOOK_XDP) {
        prog_name = "bpfw_xdp";
        prog_type = BPF_PROG_TYPE_XDP;
    }
    else {
        prog_name = "bpfw_tc";
        prog_type = BPF_PROG_TYPE_SCHED_CLS;
    }

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(obj_path, NULL);
    if (!bpf->obj) {
        bpfw_error("Error opening BPF object file %s: %s (-%d).\n", obj_path, strerror(errno), errno);
        goto free;
    }

    bpf->prog = bpf_object__find_program_by_name(bpf->obj, prog_name);
    if (!bpf->prog) {
        bpfw_error("Couldn't find %s BPF program in %s.\n", prog_name, obj_path);
        goto bpf_object__close;
    }
    
    bpf_program__set_type(bpf->prog, prog_type);

    if (check_dsa(bpf, dsa_size) != 0)
        goto bpf_object__close;

    // Try to load the BPF object into the kernel, return on error
    if (bpf_object__load(bpf->obj) != 0) {
        bpfw_error("Error loading BPF program into kernel: %s (-%d).\n", strerror(errno), errno);
        goto bpf_object__close;
    }

    return bpf;

bpf_object__close:
    bpf_object__close(bpf->obj);

free:
    free(bpf);

    return NULL;
}

void bpf_unload_program(struct bpf_handle* bpf) {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

    free(bpf);
}

int bpf_ifindex_attach_program(struct bpf_handle* bpf, __u32 ifindex) {
    if (ifindex == bpf->dsa_switch && !bpf->dsa)
        return 0;
    
    if (bpf->hook & BPFW_HOOK_XDP) {
        // Attach the program to the XDP hook
        if (bpf_xdp_attach(ifindex, bpf_program__fd(bpf->prog), get_xdp_flag(bpf->hook), NULL) != 0) {
            bpfw_error_if("Error attaching XDP program to ", ifindex, errno);
            return -1;
        }
    }
    else {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(bpf->prog));

        // Create a TC hook on the ingress of the interface
        // bpf_tc_hook_create will return an error and print an error message if the hook already exists
        int rc = bpf_tc_hook_create(&hook);
        if (rc == -EEXIST) {
            bpfw_error_if("TC hook already exists on ", ifindex, 0);
            bpfw_error("You can ignore the kernel error message.\n\n");
        }
        else if (rc != 0) {
            bpfw_error("Error creating TC hook: %s (-%d).\n", strerror(errno), errno);
            return -1;
        }

        // Attach the TC prgram to the created hook
        if (bpf_tc_attach(&hook, &opts) != 0) {
            bpfw_error_if("Error attaching TC program to ", ifindex, errno);

            hook.attach_point |= BPF_TC_EGRESS;
            bpf_tc_hook_destroy(&hook);

            return -1;
        }

        /*bpf->tc.handle   = opts.handle;
        bpf->tc.priority = opts.priority;*/
    }

    return 0;
}

void bpf_ifindex_detach_program(struct bpf_handle* bpf, __u32 ifindex) {
    if (ifindex == bpf->dsa_switch && !bpf->dsa)
        return;

    if (bpf->hook & BPFW_HOOK_XDP) {
        // Detach the program from the XDP hook
        bpf_xdp_detach(ifindex, get_xdp_flag(bpf->hook), NULL);
    }
    else {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
        //DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = bpf->tc.handle, .priority = bpf->tc.priority);

        // Detach the TC prgram
        //bpf_tc_detach(&hook, &opts);

        //if (bpf_tc_query(&hook, NULL) == -ENOENT) {
            // Needed to really destroy the qdisc hook and not just detaching the programs from it
            hook.attach_point |= BPF_TC_EGRESS;
            bpf_tc_hook_destroy(&hook);
        //}
    }
}

int bpf_ifname_attach_program(struct bpf_handle* bpf, char* ifname) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfw_error("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return -1;
    }

    return bpf_ifindex_attach_program(bpf, ifindex);
}

int bpf_ifname_detach_program(struct bpf_handle* bpf, char* ifname) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfw_error("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return -1;
    }

    bpf_ifindex_detach_program(bpf, ifindex);

    return 0;
}

int bpf_ifnames_attach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and attache the program to them
    for (int i = 0; i < ifname_size; i++) {
        int rc = bpf_ifname_attach_program(bpf, ifnames[i]);
        if (rc != 0) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--i >= 0)
                bpf_ifname_detach_program(bpf, ifnames[i]);

            return rc;
        }
    }

    return 0;
}

void bpf_ifnames_detach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and detache the program from them
    for (int i = 0; i < ifname_size; i++)
        bpf_ifname_detach_program(bpf, ifnames[i]);
}

int bpf_get_map_fd(struct bpf_handle *bpf, const char *map_name) {
    // Get the file descriptor of the BPF flow map
    int map_fd = bpf_object__find_map_fd_by_name(bpf->obj, map_name);
    if (map_fd < 0)
        bpfw_error("Error: Couldn't find BPF map %s.\n", map_name);

    return map_fd;
}

void* bpf_get_section_data(struct bpf_handle *bpf, const char *sec_name, size_t *sec_size) {
    // Find the .rodata section
    struct bpf_map *section = bpf_object__find_map_by_name(bpf->obj, sec_name);
    if (!section) {
        bpfw_error("Error: Couldn't find BPF section %s.\n", sec_name);
        return NULL;
    }

    size_t section_size;
    void *section_data = bpf_map__initial_value(section, &section_size);

    if (!section_data) {
        bpfw_error("Error: Failed to get data from BPF section %s.\n", sec_name);
        return NULL;
    }

    if (sec_size)
        *sec_size = section_size;

    return section_data;
}
