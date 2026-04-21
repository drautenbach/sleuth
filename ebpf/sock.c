#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} nat_map SEC(".maps");

SEC("cgroup/connect4")
int rewrite_connect(struct bpf_sock_addr *ctx)
{
    __u32 dst = ctx->user_ip4;

    __u32 *new_ip = bpf_map_lookup_elem(&nat_map, &dst);
    if (!new_ip)
        return 1;

    ctx->user_ip4 = *new_ip;

    return 1;
}