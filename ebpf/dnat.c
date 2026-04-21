#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7
#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // empirical IP
    __type(value, __u32); // real IP
    __uint(max_entries, 1024);
} nat_map SEC(".maps");

SEC("classifier")
int dnat_prog(struct __sk_buff *skb) {

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    bpf_printk("a\n");
if ((void*)(eth + 1) > data_end)
    return TC_ACT_OK;

        bpf_printk("ip first byte=%x\n", *(u8 *)data);

struct iphdr *ip = (void*)(eth + 1);

bpf_printk("b\n");
bpf_printk("c\n");a
if ((void*)(ip + 1) > data_end)
    return TC_ACT_OK;

if (ip->version != 4)
    return TC_ACT_OK;

bpf_printk("v=%d ihl=%d src=%x dst=%x\n", ip->version, ip->ihl, ip->saddr, ip->daddr);


    bpf_printk("d\n");
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 dst = ip->daddr;

    __u32 *real_ip = bpf_map_lookup_elem(&nat_map, &dst);
    bpf_printk("dst before=%x \n", dst);
    if (!real_ip)
        return TC_ACT_OK;

    // Rewrite destination IP
    ip->daddr = *real_ip;

    // Fix IP checksum
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), dst, *real_ip, sizeof(*real_ip));

bpf_printk("dst before=%x after=%x\n", dst, *real_ip);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";