#include "bpf_common.h"

#include <errno.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>


static void *bpf_get_section_data(struct bpf_handle *bpf, const char *sec_name, size_t *sec_size) {
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

int bpf_check_dsa(struct bpf_handle *bpf, __u32 dsa_switch, const char *dsa_proto, struct dsa_tag **dsa_tag) {
    size_t dsa_tag_sec_size;
    struct dsa_tag *dsa_tag_sec = bpf_get_section_data(bpf, DSA_TAG_SECTION, &dsa_tag_sec_size);
    if (!dsa_tag_sec)
        return BPFW_RC_ERROR;

    __s8 index = -1;
    for (int i = 0; i < dsa_tag_sec_size / sizeof(struct dsa_tag); i++) {
        if (strncmp(dsa_proto, dsa_tag_sec[i].proto, DSA_PROTO_MAX_LEN) == 0) {
            index = i;
            break;
        }
    }

    if (index == -1) {
        bpfw_error("Error: BPF program doesn't support the DSA tagging protocol '%s' of the DSA switch.\n",
            dsa_proto);

        return BPFW_RC_ERROR;
    }

    struct dsa_switch *dsa_switch_sec = bpf_get_section_data(bpf, DSA_SWITCH_SECTION, NULL);
    if (!dsa_switch_sec)
        return BPFW_RC_ERROR;

    dsa_switch_sec->ifindex = dsa_switch;
    dsa_switch_sec->proto   = index + 1;

    *dsa_tag = &dsa_tag_sec[index];

    return BPFW_RC_OK;
}


struct bpf_handle* bpf_init(const char *obj_path, struct map *iface_hooks, enum bpf_hook hook) {
    struct bpf_handle *bpf;

    bpf = malloc(sizeof(*bpf));
    if (!bpf) {
        bpfw_error("Error allocating BPF handle: %s (-%d).\n",
            strerror(errno), errno);
        goto error;
    }

    bpf->obj_loaded = false;
    bpf->tc_opts = map_create(sizeof(__u32), sizeof(struct tc_opts));

    bpf->iface_hooks = iface_hooks;
    bpf->hook = hook;

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(obj_path, NULL);
    if (!bpf->obj) {
        bpfw_error("Error opening BPF object file %s: %s (-%d).\n",
            obj_path, strerror(errno), errno);
        goto free;
    }

    return bpf;

free:
    free(bpf);
error:
    return NULL;
}

void bpf_destroy(struct bpf_handle* bpf) {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

    map_delete(bpf->tc_opts);

    free(bpf);
}
