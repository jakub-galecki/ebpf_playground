//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef struct {
    __u64 ts;
    int len;
    char buf[256];
} command;


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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} target_pids SEC(".maps");


struct  {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, void*);
    __uint(max_entries, 1);
} read_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB buffer
} output SEC(".maps");


int enter_read(struct read_enter_args *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_pids, &pid)) {
        __u64 fd = args->fd; 
        void *buf = (void*)args->buf;
        bpf_map_update_elem(&read_buffer, &pid, &buf, BPF_ANY);
    }
    return 0;   
}

int exit_read(struct read_exit_args *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_pids, &pid)) {
        int ret = args->ret;
        if (ret < 0) {
            return 0;
        }
        void **buf_ptr = bpf_map_lookup_elem(&read_buffer, &pid);
        if (!buf_ptr) {
            return 0;
        }

        command com = {};
        int n = bpf_probe_read_user_str(&com.buf, sizeof(com.buf), (void *)*buf_ptr); 
        if (n < 0) {
            return 0;
        }
        com.ts = bpf_ktime_get_ns();
        com.len = n;
        bpf_ringbuf_submit(&com, 0);
        bpf_map_delete_elem(&read_buffer, &pid);
    }
    return 0;
}