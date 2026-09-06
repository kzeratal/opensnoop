#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "config.h"
#include "opensnoop.h"
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

static int handle_event(void *ctx, void *data, size_t data_sz) {
	(void)ctx;

	const struct event *e = data;

	if (data_sz < sizeof(*e)) {
		fprintf(stderr, "Received incomplete event\n");
		return 0;
	}

	printf("%s attempts to open %s\n", e->command, e->filename);
	return 0;
}

int main(void) {
	struct opensnoop_config config = {0};
	struct opensnoop_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err = 0;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (config_load("opensnoop.ini", &config) != 0) {
		goto cleanup;
	}

	skel = opensnoop_bpf__open();
	if (!skel) {
		err = errno ? -errno : -1;
		fprintf(stderr, "Failed to open BPF skeleton: %s (%d)\n", strerror(-err), err);
		goto cleanup;
	}

	err = bpf_map__set_max_entries(skel->maps.included_executables, (__u32)config.include_count);
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

	int fd = bpf_map__fd(skel->maps.ring_buffer);
	if (fd < 0) {
		err = fd;
		fprintf(stderr, "Failed to get ring buffer map fd: %s (%d)\n", strerror(-err), err);
		goto cleanup;
	}

	rb = ring_buffer__new(fd, handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "Failed to create a ring buffer: %s (%d)\n", strerror(-err), err);
		goto cleanup;
	}

	err = opensnoop_bpf__attach(skel);
	if (err < 0) {
		fprintf(stderr, "Failed to attach BPF skeleton program: %s (%d)\n", strerror(-err), err);
		goto cleanup;
	}

	while (!stop) {
		int ret = ring_buffer__poll(rb, 100);

		if (ret == -EINTR) {
			continue;
		}

		if (ret < 0) {
			err = ret;
			fprintf(stderr, "Error polling ring buffer: %s (%d)\n", strerror(-err), err);
			break;
		}
	}

cleanup:
	if (rb) {
		ring_buffer__free(rb);
	}
	if (skel) {
		opensnoop_bpf__destroy(skel);
	}

	config_destroy(&config);
	return err ? 1 : 0;
}
