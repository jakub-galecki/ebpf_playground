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
    char comm[TASK_COMM_LEN];
    char buf[BUF_LEN];
    int buf_len;
};

//PF_PERF_OUTPUT(events);


int syscall__read(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    
    char comm[TASK_COMM_LEN];
    data.ts = bpf_ktime_get_ns();
    bpf_probe_read_user_str(&data.comm, sizeof(data.comm), comm);

    bpf_probe_read_user_str(&data.buf, sizeof(data.buf), buf);

  //  events.perf_submit(ctx, &data, sizeof(data));
    bpf_trace_printk("READ_SYSCALL: fd: <%d>, comm: <%s>\\n", fd, data.comm);
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read")
# b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="hello_world")

# def print_event(cpu, data, size):
#     event = b["events"].event(data)
#     print(f"PID: {event.pid}, Comm: {event.comm.decode('utf-8')}, Buffer: {event.buf[:event.buf_len].decode('utf-8', errors='replace')}")

# b["events"].open_perf_buffer(print_event)
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except KeyboardInterrupt:
        exit()
    print(msg)
