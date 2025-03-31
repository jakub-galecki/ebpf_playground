#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/sched.h>

#define BUF_LEN 128

struct data_t {
    u32 pid;
    u64 ts;
    char buf[BUF_LEN];
};

//BPF_PERF_OUTPUT(events);

// buf is a place where data will be stroed 
// at this point is empty 
// we have to use tracepoints - on enter store pointer, on exit read from it.
int syscall__read(struct pt_regs *ctx, unsigned int fd, char *buf, size_t count) {
    struct data_t data = {};
     
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    if (data.pid != 141002) {
        return 0;
    }

    data.ts = bpf_ktime_get_ns();

    int i = 0;
    for (i = 0; i < BUF_LEN; i++) {
        if (buf[i] == '\\0') {
            break;
        }

        data.buf[i] = buf[i];
    }

    data.buf[i] = '\\0';

    //bpf_probe_read_user(&data.buf, sizeof(data.buf), buf);
  //  events.perf_submit(ctx, &data, sizeof(data));

    bpf_trace_printk("buf: %s \\n", data.buf);
  
    return 0;
}