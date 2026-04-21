To compile dnat.o:

apt-get update
apt-get install -y clang llvm libbpf-dev bpftool linux-headers-amd64 #or arm64
clang -O2 -g -target bpf -c dnat.c -o dnat.o
-------


to attach to interface (TC - dnat.o):
apt-get update
apt-get install -y iproute2

for eth0:
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf da obj dnat.o sec classifier
tc filter add dev eth0 egress bpf da obj dnat.o sec classifier
tc filter show dev eth0 ingress # to verify

for lo:
tc qdisc add dev lo clsact
tc filter add dev lo ingress bpf da obj dnat.o sec classifier


to trace:


----
to attach using bpftool (sock.o)
apt install linux-image-amd64 linux-headers-amd64
clang -O2 -g -target bpf -c sock.c -o sock.o
mkdir /sys/fs/cgroup/test
bpftool prog load sock.o /sys/fs/bpf/dnat #type cgroup/connect4
bpftool cgroup attach /sys/fs/cgroup/unified connect4 pinned /sys/fs/bpf/dnat
----


to setup as router:

local testing: ip addr add 1.2.3.4/32 dev lo
enable forwarding: sysctl -w net.ipv4.ip_forward=1