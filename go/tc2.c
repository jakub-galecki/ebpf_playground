//go:build ignore

#include <linux/sched.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

struct command {
    u64 ts;
    int len;
    char buf[256];
};

// map of pids that read should be monitored
struct  {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} target_pids SEC(".maps");


struct  {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, void*);
    __uint(max_entries, 1);
} read_buffer SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __type(value, struct command);
    __uint(max_entries, 1 << 24); // 16MB buffer
} output SEC(".maps");


struct read_enter_args {
        u64 __do_not_use__;
        int __syscall_nr;
        char __pad_12;
        char __pad_13;
        char __pad_14;
        char __pad_15;
        u64 fd;
        char * buf;
        long count;
};

SEC("tracepoint/syscalls/sys_enter_read")
int enter_read(struct read_enter_args *args) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_pids, &pid)) {
        void *buf = (void*)args->buf;
        bpf_map_update_elem(&read_buffer, &pid, &buf, BPF_NOEXIST);
    }
    return 0;
}

struct read_exit_args {
        u64 __do_not_use__;
        int __syscall_nr;
        char __pad_12;
        char __pad_13;
        char __pad_14;
        char __pad_15;
        long ret;
};

SEC("tracepoint/syscalls/sys_exit_read")
int exit_read(struct read_exit_args *args) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_pids, &pid)) {
        int ret = args->ret;
        if (ret < 0) {
            return 0;
        }
        void **buf_ptr = bpf_map_lookup_elem(&read_buffer, &pid);
        if (!buf_ptr) {
            return 0;
        }

        struct command *com = bpf_ringbuf_reserve(&output, sizeof(struct command), 0);
        if (!com) {
            return 0;
        }
        int n = bpf_probe_read_user_str(com->buf, sizeof(com->buf), (void *)*buf_ptr);
        if (n < 0) {
            bpf_ringbuf_discard(com, 0);
            return 0;
        }
        com->ts = bpf_ktime_get_ns();
        com->len = n;
        bpf_ringbuf_submit(com, 0);
        bpf_map_delete_elem(&read_buffer, &pid);
    }
    return 0;
}

