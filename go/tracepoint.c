//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

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


// logs in  /sys/kernel/debug/tracing/trace

char __license[] SEC("license") = "Dual MIT/GPL";

struct command {
    __u64 ts;
    int len;
    char buf[256];
};

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

struct read_exit_args {
    u64 __do_not_use__;
    int __syscall_nr;
    char __pad_12;
    char __pad_13;
    char __pad_14;
    char __pad_15;
    long ret;
};

// in go ebpf we can use global variable to store target pid
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
    __uint(max_entries, 8);
} read_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __type(value, struct command);
    __uint(max_entries, 1 << 24); // 16MB buffer
} output SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_read")
int enter_read(struct read_enter_args *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&target_pids, &pid)) {
        return 0;
    }
    void *buf = (void*)args->buf;
    int n =  bpf_map_update_elem(&read_buffer, &pid, &buf, BPF_ANY);
    if (n < 0) {
        bpf_printk("[enter_read] updating map with pointer to buf failed with err: %d\n",  n);
        return 1;
    }
    return 0;   
}

SEC("tracepoint/syscalls/sys_exit_read")
int exit_read(struct read_exit_args *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&target_pids, &pid)) {
        return 0;
    }

    int ret = args->ret;
    if (ret <= 0) {
        bpf_printk("[exit_read] return value less than 0\n");
        bpf_map_delete_elem(&read_buffer, &pid);
        return 1;
    }
    void **buf_ptr = bpf_map_lookup_elem(&read_buffer, &pid);
    if (!buf_ptr) {
        bpf_printk("[exit_read] empty read_buffer for pid %d\n", pid);
        bpf_map_delete_elem(&read_buffer, &pid);
        return 1;
    }

    struct command *com = bpf_ringbuf_reserve(&output, sizeof(struct command), 0);
    if (!com) {
        bpf_printk("[exit_read] bpf_ringbuf_reserve failed\n");
        bpf_map_delete_elem(&read_buffer, &pid);
        return 1;
    }
    int n = bpf_probe_read_user_str(com->buf, sizeof(com->buf), (void *)*buf_ptr); 
    if (n < 0) {
        bpf_printk("[exit_read] reading buffer %p string failed %d, expected: %d\n", *buf_ptr, n, ret);
        bpf_map_delete_elem(&read_buffer, &pid);
        bpf_ringbuf_discard(com, 0);
        return 1;
    }
    // this can be used to track duration, but is useless to track timestamp
    // as CLOCK_MONOTONIC is used.
    com->ts = bpf_ktime_get_ns();
    com->len = n;
    bpf_ringbuf_submit(com, 0);
    bpf_map_delete_elem(&read_buffer, &pid);
    return 0;
}
