#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "opensnoop.skel.h"

static volatile sig_atomic_t stop = 0;

static void sig_handler(int signo) {
    stop = 1;
}

int main(void) {
    struct opensnoop_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = opensnoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = opensnoop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton program\n");
        goto cleanup;
    }

    printf("Tracing file openings with Skeleton! Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to view.\n");

    while (!stop) {
        sleep(1);
    }

cleanup:
    opensnoop_bpf__destroy(skel);
    return 0;
}
