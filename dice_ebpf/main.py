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

prog = """
#include <uapi/linux/ptrace.h>

int hello_world(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="hello_world")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="hello_world")

print("Tracing processes in the system... Ctrl-C to end")
# header

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        # if pid != target_pid:
        #     continue
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))