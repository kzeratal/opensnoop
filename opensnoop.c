#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "opensnoop.skel.h"
#include "config.h"

static volatile sig_atomic_t stop = 0;

static void sig_handler(int signo) {
	(void)signo;
	stop = 1;
}

int main(void) {
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct opensnoop_config config = {0};
	if (config_load("opensnoop.ini", &config) != 0) {
		return -1;
	}

	struct opensnoop_bpf *skel = opensnoop_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		config_destroy(&config);
		return 1;
	}

	int err = opensnoop_bpf__attach(skel);
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
	config_destroy(&config);
	return err ? 1 : 0;
}
