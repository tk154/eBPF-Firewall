#ifndef BPFW_BPF_H
#define BPFW_BPF_H

#include <stdbool.h>

#include "../common_user.h"
#include "../netlink/netlink.h"
#include "../map/map.h"


// Struct to keep BPF object and program pointers together
struct bpf_handle;
struct bpf_map;

struct bpf_handle* bpf_init(const char* obj_path, enum bpf_hook hook);
int bpf_init_rss(struct bpf_handle *bpf, const char *rss_prog_name);
void bpf_destroy(struct bpf_handle *bpf);

int bpf_attach_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h, struct map *iface_hooks, bool auto_attach);
int bpf_iface_attach_program(struct bpf_handle *bpf, struct netlink_handle *nl, __u32 ifindex, enum bpf_hook hook);
void bpf_detach_program(struct bpf_handle* bpf, struct map *iface_hooks);

enum bpf_hook bpf_ifindex_get_hook(struct bpf_handle *bpf, __u32 ifindex);

struct bpf_map *bpf_get_map(struct bpf_handle* bpf, const char *map_name);
void bpf_free_map(struct bpf_map *map);

int bpf_set_map_max_entries(struct bpf_handle *bpf, const char *map_name, __u32 new_max_entries);
int bpf_check_dsa(struct bpf_handle *bpf, __u32 dsa_switch, const char *dsa_proto, struct dsa_tag **dsa_tag);

int bpf_map_lookup_entry(struct bpf_map *map, const void *key, void *value);
int bpf_map_update_entry(struct bpf_map *map, const void *key, const void *value);
int bpf_map_delete_entry(struct bpf_map *map, const void *key);

int bpf_map_first_entry(struct bpf_map *map, void *key, void *value);
int bpf_map_next_entry(struct bpf_map *map, void *key, void *value);


#define bpf_map_for_each_entry(map, key, value, block)  \
    do {                                                \
        int ret = bpf_map_first_entry(map, key, value); \
        while (ret == BPFW_RC_OK) {                     \
            block;                                      \
            ret = bpf_map_next_entry(map, key, value);  \
        }                                               \
        if (ret != -EOF)                                \
            return BPFW_RC_ERROR;                       \
    } while (0);


#endif
