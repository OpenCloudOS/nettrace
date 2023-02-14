#ifndef _H_BPF_UTILS
#define _H_BPF_UTILS

#include <bpf/bpf.h>
#include <net_utils.h>

#include "bpf/skb_shared.h"

#define BPF_PROG_FD(name)	(bpf_program__fd(obj->progs.name))
#define BPF_MAP_FD(name)	(bpf_map__fd(obj->maps.name))

typedef struct {
	pkt_args_t pkt;
#ifdef BPF_DEBUG
	bool bpf_debug;
#endif
#ifdef DEFINE_BPF_ARGS
	DEFINE_BPF_ARGS();
#endif
} bpf_args_t;

extern long int syscall (long int __sysno, ...);

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

int
perf_output_cond(int fd, perf_buffer_sample_fn cb, perf_buffer_lost_fn lost,
		 bool *stop);

static inline int perf_output(int fd, perf_buffer_sample_fn fn)
{
	return perf_output_cond(fd, fn, NULL, NULL);
}

int compat_bpf_attach_kprobe(int fd, char *name, bool ret);

#endif
