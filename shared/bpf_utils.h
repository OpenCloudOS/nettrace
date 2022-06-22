#ifndef _H_BPF_UTILS
#define _H_BPF_UTILS

#include <bpf/libbpf.h>

#define BPF_PROG_FD(name)	(bpf_program__fd(obj->progs.name))
#define BPF_MAP_FD(name)	(bpf_map__fd(obj->maps.name))
#define BPF_LINK_FD(name)	(bpf_link__fd(obj->links.name))

static inline void
perf_output_cond(int fd, perf_buffer_sample_fn fn, bool *stop)
{
	struct perf_buffer_opts pb_opts = {
		.sample_cb = fn
	};
	struct perf_buffer *pb;
	int ret;

	pb = perf_buffer__new(fd, 8, &pb_opts);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return;
	}

	while ((ret = perf_buffer__poll(pb, 1000)) >= 0)
		if (stop && *stop)
			break;
}

static inline void perf_output(int fd, perf_buffer_sample_fn fn)
{
	perf_output_cond(fd, fn, NULL);
}

#endif
