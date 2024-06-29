#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <linux/bpf.h>
#include "../netlink/netlink.h"


// Struct to keep BPF object and program pointers together
struct bpf_handle;

/**
 * Load a BPF object including its map and program into the kernel
 * @param prog_path Path to the BPF object
 * @param prog_type Can be either BPF_PROG_TYPE_XDP for XDP or BPF_PROG_TYPE_SCHED_CLS for TC programs
 * @returns On success, a pointer to a dynamically allocated bpf_handle struct, NULL otherwise
**/
struct bpf_handle* bpf_load_program(const char* prog_path, enum bpf_prog_type prog_type, struct netlink_handle *netlink_h, bool dsa);

/**
 * Unload a BPF object including its map and program from the kernel
 * @param bpf A pointer to a valid bpf_handle struct. 
 * The allocated memory for the struct will be freed so the pointer should not be used anymore afterwards.
**/
void bpf_unload_program(struct bpf_handle* bpf);

/**
 * Attach a BPF program to an interface
 * @param prog A pointer to the to-be-attached BPF program
 * @param ifname The name of the network interface where the program should be attached to
 * @returns 0 on success, -1 if the program is not of type XDP or TC, errno for other errors
 * **/
int bpf_if_attach_program(struct bpf_handle* bpf, char* ifname, __u32 xdp_flags);

/**
 * Detach a BPF program from an interface
 * @param prog A pointer to the to-be-unattached BPF program
 * @param ifname The name of the network interface where the program should be detached from
 * **/
void bpf_if_detach_program(struct bpf_handle* bpf, char* ifname, __u32 xdp_flags);

/**
 * Attach a BPF program to multiple interfaces
 * @param prog A pointer to the to-be-attached BPF program
 * @param ifnames An array containing the interface names where the program should be attached to
 * @param ifname_size The size of the ifnames array
 * @returns 0 on success, -1 if the program is not of type XDP or TC, errno for other errors
 * **/
int bpf_ifs_attach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size, __u32 xdp_flags);

/**
 * Detach a BPF program from multiple interfaces
 * @param prog A pointer to the to-be-detached BPF program
 * @param ifnames An array containing the interface names where the program should be detached from
 * @param ifname_size The size of the ifnames array
 * **/
void bpf_ifs_detach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size, __u32 xdp_flags);

/**
 * Attach a BPF program to all non-virtual network interfaces
 * @param prog A pointer to the to-be-attached BPF program
 * @returns 0 on success, -1 if the program is not of type XDP or TC, errno for other errors
 * **/
int bpf_attach_program(struct bpf_handle* bpf, __u32 xdp_flags, struct netlink_handle *netlink_h);

/**
 * Detach a BPF program from all non-virtual network interfaces
 * @param prog A pointer to the to-be-detached BPF program
 * @returns 0 on success, errno if the network interfaces couldn't be retrieved
 * **/
int bpf_detach_program(struct bpf_handle* bpf, __u32 xdp_flags, struct netlink_handle *netlink_h);

int bpf_get_map_fd(struct bpf_handle* bpf, const char *map_name);


#endif
