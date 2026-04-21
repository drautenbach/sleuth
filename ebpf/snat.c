#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // backend IP
    __type(value, __u32); // original client IP
    __uint(max_entries, 1024);
} snat_map SEC(".maps");

SEC("classifier")
int snat_prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    struct iphdr *ip = data;

    if (ip->version != 4 || ip->ihl < 5)
        return TC_ACT_OK;

    __u32 src = ip->saddr;

    __u32 *orig_src = bpf_map_lookup_elem(&snat_map, &src);
    if (!orig_src)
        return TC_ACT_OK;

    __u32 old_src = src;
    __u32 new_src = *orig_src;

    ip->saddr = new_src;

    bpf_l3_csum_replace(
        skb,
        offsetof(struct iphdr, check),
        old_src,
        new_src,
        sizeof(__u32)
    );

    bpf_printk("SNAT %x -> %x", old_src, new_src);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";