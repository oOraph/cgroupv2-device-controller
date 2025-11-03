// device_filter.c (CO-RE / BTF-based)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// wildcard major/minor, safe to use u32 max: this won't conflict with a real major or minor because they are encoded
// on 20 bits
#define WILDCARD ((__u32)~0U)

struct dev_key {
    __u32 major;
    __u32 minor;
    __u32 dev_type; // BPF_DEVCG_DEV_BLOCK or BPF_DEVCG_DEV_CHAR
};

// Each value is a bitmask of allowed access flags, e.g.
//   BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD
struct dev_val {
    __u32 allow_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dev_key);
    __type(value, struct dev_val);
} dev_whitelist SEC(".maps");

SEC("cgroup/dev")
int device_filter(struct bpf_cgroup_dev_ctx *ctx)
{
    __u32 access_type = ctx->access_type & 0xFFFF;
    __u32 dev_type    = ctx->access_type >> 16;

    struct dev_key key;
    struct dev_val *v;

    // (1) exact <major,minor,dev_type> match
    key.major = ctx->major;
    key.minor = ctx->minor;
    key.dev_type = dev_type;
    v = bpf_map_lookup_elem(&dev_whitelist, &key);
    if (v && (v->allow_flags & access_type) == access_type)
        return 1;

    // (2) wildcard minor
    key.minor = WILDCARD;
    v = bpf_map_lookup_elem(&dev_whitelist, &key);
    if (v && (v->allow_flags & access_type) == access_type)
        return 1;

    // (3) wildcard major (I currently do not see any case of this one, nvm, who can more can less)
    key.major = WILDCARD;
    key.minor = ctx->minor;
    v = bpf_map_lookup_elem(&dev_whitelist, &key);
    if (v && (v->allow_flags & access_type) == access_type)
        return 1;

    // (4) wildcard both (example: all char devs)
    key.minor = WILDCARD;
    v = bpf_map_lookup_elem(&dev_whitelist, &key);
    if (v && (v->allow_flags & access_type) == access_type)
        return 1;

    return 0;
}

char _license[] SEC("license") = "GPL";
