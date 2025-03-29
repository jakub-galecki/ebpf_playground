#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 pid;
    int uid;
    char command[20];
    u64 runtime;
};

BPF_HASH(process_time_map);
BPF_PERF_OUTPUT(output);

int set_timestamp(void *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;  /* BPF helper function to get PID and TGID */
    u64 ts = bpf_ktime_get_ns();                 /* BPF helper function to get time as nanoseconds */
    process_time_map.update(&pid, &ts);          /* Update the hash table with the new time value for this PID. */ 
    return 0;
}

int send_runtime(void *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;                /* BPF helper function to get PID and TGID */
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;          /* BPF helper function to get UID */
    bpf_get_current_comm(&data.command, sizeof(data.command));  /* BPF helper function to get the name of the executable/command */
    u64 *ts = process_time_map.lookup(&data.pid);               /* Look for an entry in the hash table with a key matching the PID */
    if (ts != NULL) {
        data.runtime = bpf_ktime_get_ns() - *ts;                /* Calculating the process runtime from start to finish */
        output.perf_submit(ctx, &data, sizeof(data));           /* Puts that data into the map */
    }
    return 0;
}