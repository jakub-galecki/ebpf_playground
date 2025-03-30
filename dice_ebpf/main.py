#!/usr/bin/python3
from bcc import BPF
from bcc.utils import printb
import sys

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# target_pid = sys.argv[1]

# print(bcolors.OKCYAN + "Reading for pid: " + target_pid + bcolors.ENDC)


# __user - indicates that pointer is in the userspace
prog = """
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

    // bpf_probe_read_user(&data.buf, sizeof(data.buf), buf);
  //  events.perf_submit(ctx, &data, sizeof(data));

    bpf_trace_printk("buf: %s \\n", data.buf);
  
    return 0;
}
"""

b = BPF(text=prog)
fname = b.get_syscall_fnname("read")  # __x64_sys_read
print(fname)
b.attach_kprobe(event=fname, fn_name="syscall__read")
# b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="hello_world")

# def print_event(cpu, data, size):
#     event = b["events"].event(data)
#     if event.pid != 141002:
#         return
#     print(f"PID: {event.pid}, Buffer: {event.buf[:]}")

# b["events"].open_perf_buffer(print_event)
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    print(msg)

