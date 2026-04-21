#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

#define OLD_IP 0x0A7B7B7B
#define NEW_IP 0x8EFB9877

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dummy_map SEC(".maps");

static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    return ~csum;
}

static __always_inline __u32 csum_add(__u32 sum, __u32 val)
{
    sum += val;
    return (sum & 0xffffffff);
}

SEC("tc")
int dnat_tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    unsigned char *p = data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->daddr != bpf_htonl(OLD_IP))
        return TC_ACT_OK;

    __u32 old = ip->daddr;
    __u32 new = bpf_htonl(NEW_IP);

    /* --- update checksum (RFC 1624 incremental update) --- */
    __u32 csum = ~ip->check;

    csum = csum_add(csum, ~old);
    csum = csum_add(csum, new);

    ip->check = csum_fold(csum);

    /* --- rewrite destination IP --- */
    ip->daddr = new;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";