#ifndef _H_BPF_UTILS
#define _H_BPF_UTILS

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_PROG_FD(name)	(bpf_program__fd(obj->progs.name))
#define BPF_MAP_FD(name)	(bpf_map__fd(obj->maps.name))
#define BPF_LINK_FD(name)	(bpf_link__fd(obj->links.name))

#ifdef MAP_CONFIG
#define bpf_set_config(skel, sec, value) do {		\
	int fd = bpf_map__fd(skel->maps.m_config);	\
	u8 buf[CONFIG_MAP_SIZE] = {};			\
	int key = 0;					\
							\
	if (fd < 0) {					\
		pr_err("failed to get config map: %d\n",\
		       fd);				\
		break;					\
	}						\
							\
	*(bpf_args_t *)(void *)buf = value;		\
	bpf_map_update_elem(fd, &key, buf, 0);		\
} while (0)

#define bpf_set_config_field(skel, sec, name, value) do { \
	int fd = bpf_map__fd(skel->maps.m_config);	\
	u8 buf[CONFIG_MAP_SIZE] = {};			\
	bpf_args_t *args = (void *)buf;			\
	int key = 0;					\
							\
	if (fd < 0) {					\
		pr_err("failed to get config map: %d\n",\
		       fd);				\
		break;					\
	}						\
							\
	bpf_map_lookup_elem(fd, &key, args);		\
	args->name = value;				\
	bpf_map_update_elem(fd, &key, args, 0);		\
} while (0)
#else
#define bpf_set_config(skel, sec, value) skel->sec->_bpf_args = value
#define bpf_set_config_field(skel, sec, name, value) skel->sec->_bpf_args.name = value
#endif

static inline void
perf_output_cond(int fd, perf_buffer_sample_fn cb, perf_buffer_lost_fn lost,
		 bool *stop)
{
	struct perf_buffer_opts pb_opts = {
		.sample_cb = cb,
		.lost_cb = lost,
	};
	struct perf_buffer *pb;
	int ret;

	pb = perf_buffer__new(fd, 1024, &pb_opts);
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
	perf_output_cond(fd, fn, NULL, NULL);
}

#endif
