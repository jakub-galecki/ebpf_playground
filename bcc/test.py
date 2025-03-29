#!/usr/bin/python3
from bcc import BPF
from bcc.utils import printb


with open("hash_map.c", "r") as f:
    bpf_program = f.read()

# Loading the eBPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="set_timestamp")
b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="send_runtime")


print("Tracing processes in the system... Ctrl-C to end")
# header
print("%-6s %-6s %-20s %s" % ("PID", "UID", "COMM", "RUNTIME"))

def print_event(cpu, data, size):
    """Callback function that will output the event data"""
    data = b["output"].event(data)  # BCC allows this simple map access from user spcae
    print("%-6s %-6s %-20s %s" % (data.pid, data.uid, data.command.decode(), data.runtime/10**9))

b["output"].open_perf_buffer(print_event)  # Opens the perf ring buffer, sending our callback function
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()