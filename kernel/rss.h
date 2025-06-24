#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "parse_header.h"


struct rss_ipv4_flow {
    __be32 src_ip, dest_ip;
    __be16 src_port, dest_port;
    __u8 protocol;
    __u8 pad[3];
};

struct rss_ipv6_flow {
    __be32 src_ip[4], dest_ip[4];
    __be16 src_port, dest_port;
    __u8 protocol;
    __u8 pad[3];
};

struct cpu_iterator {
    struct bpf_spin_lock semaphore;
    __u32 cpu;
};


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct rss_ipv4_flow);
    __type(value, __u32);
    __uint(max_entries, RSS_FLOW_MAP_DEFAULT_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} BPFW_RSS_IPV4_FLOW_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct rss_ipv6_flow);
    __type(value, __u32);
    __uint(max_entries, RSS_FLOW_MAP_DEFAULT_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} BPFW_RSS_IPV6_FLOW_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
    __uint(max_entries, 1);
} BPFW_CPU_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cpu_iterator);
    __uint(max_entries, 1);
} cpu_iterator_map SEC(".maps");

SEC(BPFW_CPU_COUNT_SECTION)
__u32 cpu_count = 1;


SEC("xdp")
int round_robin(struct xdp_md *xdp)
{
    struct cpu_iterator *iterator;
    __u32 cpu_idx, key = 0;

    iterator = bpf_map_lookup_elem(&cpu_iterator_map, &key);
    if (!iterator)
        return XDP_ABORTED;

    bpf_spin_lock(&iterator->semaphore);
    cpu_idx = iterator->cpu;

    if (++iterator->cpu == cpu_count)
        iterator->cpu = 0;

    bpf_spin_unlock(&iterator->semaphore);

    return bpf_redirect_map(&BPFW_CPU_MAP, cpu_idx, 0);
}

SEC("xdp")
int flow_steering(struct xdp_md *xdp)
{
    __u32 *cpu_idx, new_cpu, key = 0;
    struct cpu_iterator *iterator;
    struct packet_header header;
    struct rss_ipv4_flow flow4;
    struct rss_ipv6_flow flow6;
	struct packet_data pkt;
    void *flow, *flow_map;

    pkt.in_ifindex = xdp->ingress_ifindex;
    pkt.data = (void *)(long)xdp->data;
    pkt.data_end = (void *)(long)xdp->data_end;
    pkt.p = pkt.data;

    if (!parse_l2_header(xdp, true, &pkt, &header.l2))
        return XDP_PASS;

    if (!parse_l3_header(&pkt, header.l2.proto, &header.l3))
        return XDP_PASS;

    if (!parse_l4_header(&pkt, header.l3.proto, &header.l4))
        return XDP_PASS;

    if (header.l3.family == AF_INET) {
        ip4cpy(&flow4.src_ip, header.l3.src_ip);
        ip4cpy(&flow4.dest_ip, header.l3.dest_ip);
        flow4.src_port = *header.l4.src_port;
        flow4.dest_port = *header.l4.dest_port;
        flow4.protocol = header.l3.proto;
        memset(flow4.pad, 0, sizeof(flow4.pad));

        flow = &flow4;
        flow_map = &BPFW_RSS_IPV4_FLOW_MAP;
    }
    else {
        ip6cpy(flow6.src_ip, header.l3.src_ip);
        ip6cpy(flow6.dest_ip, header.l3.dest_ip);
        flow6.src_port = *header.l4.src_port;
        flow6.dest_port = *header.l4.dest_port;
        flow6.protocol = header.l3.proto;
        memset(flow6.pad, 0, sizeof(flow6.pad));

        flow = &flow6;
        flow_map = &BPFW_RSS_IPV6_FLOW_MAP;
    }

    cpu_idx = bpf_map_lookup_elem(flow_map, flow);
    if (!cpu_idx) {
        iterator = bpf_map_lookup_elem(&cpu_iterator_map, &key);
        if (!iterator)
            return XDP_ABORTED;

        bpf_spin_lock(&iterator->semaphore);

        new_cpu = iterator->cpu;
        if (++iterator->cpu == cpu_count)
            iterator->cpu = 0;

        bpf_spin_unlock(&iterator->semaphore);

        bpf_map_update_elem(flow_map, flow, &new_cpu, BPF_NOEXIST);
        cpu_idx = &new_cpu;
    }

    return bpf_redirect_map(&BPFW_CPU_MAP, *cpu_idx, 0);
}
