#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "config.h"
#include "opensnoop.skel.h"

static volatile sig_atomic_t stop = 0;

static void sig_handler(int signo) {
	(void)signo;
	stop = 1;
}

static int populate_include_map(struct opensnoop_bpf *skel, const struct opensnoop_config *config) {
	const __u8 included = 1;

	for (size_t i = 0; i < config->include_count; i++) {
		int err = bpf_map__update_elem(
			skel->maps.included_executables,
			config->includes[i].value,
			sizeof(config->includes[i].value),
			&included,
			sizeof(included),
			BPF_NOEXIST
		);
		if (err < 0) {
			fprintf(stderr, "Failed to update include map entry %s: %s (%d)\n", config->includes[i].value, strerror(-err), err);
			return err;
		}
	}

	return 0;
}

int main(void) {
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct opensnoop_config config = {0};
	if (config_load("opensnoop.ini", &config) != 0) {
		return 1;
	}

	struct opensnoop_bpf *skel = opensnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		config_destroy(&config);
		return 1;
	}

	int err = bpf_map__set_max_entries(skel->maps.included_executables, (__u32)config.include_count);
	if (err < 0) {
		fprintf(stderr, "Failed to set map capacity to %zu: %s (%d)\n", config.include_count, strerror(-err), err);
		goto cleanup;
	}

	err = opensnoop_bpf__load(skel);
	if (err < 0) {
		fprintf(stderr, "Failed to load BPF skeleton: %s (%d)\n", strerror(-err), err);
		goto cleanup;
	}

	err = populate_include_map(skel, &config);
	if (err < 0) {
		goto cleanup;
	}

	err = opensnoop_bpf__attach(skel);
	if (err < 0) {
		fprintf(stderr, "Failed to attach BPF skeleton program: %s (%d)\n", strerror(-err), err);
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
