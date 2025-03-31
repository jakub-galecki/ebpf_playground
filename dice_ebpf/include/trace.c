#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct {
    u64 ts;
    int len;
    char buf[256];
} command;


// map of pids that read should be monitored
BPF_HASH(target_pids, u32, bool);
BPF_HASH(read_buffer, u32, void*);
BPF_PERF_OUTPUT(output);


TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pids.lookup(&pid)) {
        u64 fd = args->fd; 
        void *buf = (void*)args->buf;
        read_buffer.insert(&pid, &buf);
    }
    return 0;   
}


TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pids.lookup(&pid)) {
        int ret = args->ret;
        if (ret < 0) {
            return 0;
        }
        void **buf_ptr = read_buffer.lookup(&pid);
        if (!buf_ptr) {
            return 0;
        }

        command com = {};
        int n = bpf_probe_read_user_str(&com.buf, sizeof(com.buf), (void *)*buf_ptr); 
        if (n < 0) {
            bpf_trace_printk("error copying data from buffer");            
            return 0;
        }
        com.ts = bpf_ktime_get_ns();
        com.len = n;
        output.perf_submit(args, &com, sizeof(com));
        read_buffer.delete(&pid);
    }
    return 0;  
}
