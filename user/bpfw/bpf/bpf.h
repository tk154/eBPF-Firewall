#ifndef BPFW_BPF_H
#define BPFW_BPF_H

#include <stdbool.h>

#include "../common_user.h"
#include "../netlink/netlink.h"
#include "../map/map.h"


// Struct to keep BPF object and program pointers together
struct bpf_handle;

struct bpf_map {
    const char *name;
    int fd;
};


/**
 * Load a BPF object including its map and program into the kernel
 * @param obj_path Path to the BPF object
 * @param prog_type Can be either BPF_PROG_TYPE_XDP for XDP or BPF_PROG_TYPE_SCHED_CLS for TC programs
 * @returns On success, a pointer to a dynamically allocated bpf_handle struct, NULL otherwise
**/
struct bpf_handle* bpf_init(const char* obj_path, struct map *iface_hooks, enum bpf_hook hook);
void bpf_destroy(struct bpf_handle *bpf);
//int bpf_load_program(struct bpf_handle* bpf);

/**
 * Unload a BPF object including its map and program from the kernel
 * @param bpf A pointer to a valid bpf_handle struct. 
 * The allocated memory for the struct will be freed so the pointer should not be used anymore afterwards.
**/
/*void bpf_unload_program(struct bpf_handle* bpf);

int  bpf_ifindex_attach_program(struct bpf_handle* bpf, __u32 ifindex);
void bpf_ifindex_detach_program(struct bpf_handle* bpf, __u32 ifindex);*/

/**
 * Attach a BPF program to an interface
 * @param prog A pointer to the to-be-attached BPF program
 * @param ifname The name of the network interface where the program should be attached to
 * @returns 0 on success, -1 if the program is not of type XDP or TC, errno for other errors
 * **/
//int bpf_ifname_attach_program(struct bpf_handle* bpf, char* ifname);

/**
 * Detach a BPF program from an interface
 * @param prog A pointer to the to-be-unattached BPF program
 * @param ifname The name of the network interface where the program should be detached from
 * **/
//int bpf_ifname_detach_program(struct bpf_handle* bpf, char* ifname);

/**
 * Attach a BPF program to multiple interfaces
 * @param prog A pointer to the to-be-attached BPF program
 * @param ifnames An array containing the interface names where the program should be attached to
 * @param ifname_size The size of the ifnames array
 * @returns 0 on success, -1 if the program is not of type XDP or TC, errno for other errors
 * **/
//int bpf_ifnames_attach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifnames_size);

/**
 * Detach a BPF program from multiple interfaces
 * @param prog A pointer to the to-be-detached BPF program
 * @param ifnames An array containing the interface names where the program should be detached from
 * @param ifname_size The size of the ifnames array
 * **/
//void bpf_ifnames_detach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifnames_size);

/**
 * Attach a BPF program to all non-virtual network interfaces
 * @param prog A pointer to the to-be-attached BPF program
 * @returns 0 on success, -1 if the program is not of type XDP or TC, errno for other errors
 * **/
int bpf_attach_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h, bool auto_attach);

/**
 * Detach a BPF program from all non-virtual network interfaces
 * @param prog A pointer to the to-be-detached BPF program
 * @returns 0 on success, errno if the network interfaces couldn't be retrieved
 * **/
void bpf_detach_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h, bool auto_attach);

int bpf_iface_attach_program(struct bpf_handle *bpf, struct netlink_handle *nl, __u32 ifindex, const char *ifname);
int bpf_iface_detach_program(struct bpf_handle *bpf, struct netlink_handle *nl, __u32 ifindex, const char *ifname);

struct bpf_map bpf_get_map(struct bpf_handle* bpf, const char *map_name);
//void *bpf_get_section_data(struct bpf_handle *bpf, const char *sec_name, size_t *sec_size);
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
