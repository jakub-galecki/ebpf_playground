//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

// logs in  /sys/kernel/debug/tracing/trace

char __license[] SEC("license") = "Dual BSD/GPL";

struct command {
    __u64 ts;
    int len;
    char buf[256];
};

struct read_enter_args {
	__u64 __unused__;
	int __syscall_nr;	
	unsigned int fd;
    char * buf;	
	unsigned int count;
};

struct read_exit_args {
	__u64 __unused__;
	int __syscall_nr;	
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
    __type(value, char*);
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
    char *buf = args->buf;
    bpf_printk("[enter_read] putting pointer: %p for pid: %d, original pointer: %p\n", buf, pid, args->buf);
    bpf_map_update_elem(&read_buffer, &pid, &buf, BPF_ANY);
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
        return 1;
    }
    void **buf_ptr = bpf_map_lookup_elem(&read_buffer, &pid);
    if (!buf_ptr) {
        bpf_printk("[exit_read] empty read_buffer for pid %d\n", pid);
        return 1;
    }

    struct command *com = bpf_ringbuf_reserve(&output, sizeof(struct command), 0);
    if (!com) {
        bpf_printk("[exit_read] bpf_ringbuf_reserve failed %d\n");
        return 1;
    }

    bpf_printk("[exit_read] reading pointer: %p for pid: %d\n", *buf_ptr, pid);

    int n = bpf_probe_read_user_str(com->buf, sizeof(com->buf), (char *)*buf_ptr); 
    if (n < 0) {
        bpf_printk("[exit_read] reading buffer string failed %d, expected: %d\n", n, ret);
        bpf_ringbuf_discard(com, 0);
        return 1;
    }
    com->ts = bpf_ktime_get_ns();
    com->len = n;
    bpf_ringbuf_submit(com, 0);
    bpf_map_delete_elem(&read_buffer, &pid);
    return 0;
}
