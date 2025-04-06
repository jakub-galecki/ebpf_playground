#!/usr/bin/python3
from bcc import BPF, DEBUG_PREPROCESSOR
from bcc.utils import printb
import sys
import ctypes
import os

DEBUG = int(os.getenv("DEBUG", 0))

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

class Command(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("len", ctypes.c_int),
        ("buffer", ctypes.c_char*256)
    ]

def print_event(cpu, data, size):
    e = ctypes.cast(data, ctypes.POINTER(Command)).contents
    print("%s %s %s" % (e.ts, e.len, e.buffer))

def main():
    raw = sys.argv[1]
    if DEBUG == 1: print(bcolors.OKCYAN + "Reading for pid: " + raw + bcolors.ENDC)
    with open("./include/trace.c", "r") as f:
        prog = f.read()
    b = BPF(text=prog, debug=DEBUG_PREPROCESSOR)
    # b.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="enter_read")
    # b.attach_tracepoint(tp="syscalls:sys_exit_read", fn_name="exit_read")
    for i in raw.split(","):
        pid = ctypes.c_uint32(int(i))
        if DEBUG == 2: print(pid)
        b["target_pids"][pid] = ctypes.c_bool(True)
    b["output"].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()
