#ifndef _H_BPF_UTILS
#define _H_BPF_UTILS

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys_utils.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#define BPF_PROG_FD(name)	(bpf_program__fd(obj->progs.name))
#define BPF_MAP_FD(name)	(bpf_map__fd(obj->maps.name))

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

static inline int compat_bpf_attach_kprobe(int fd, char *name, bool ret)
{
	struct perf_event_attr attr = {};
	char buf[1024], target[128];
	int id, err;

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	sprintf(target, "%s%s", ret ? "ret_" : "", name);
	sprintf(buf, "/sys/kernel/debug/tracing/events/kprobes/%s/id",
		target);
	if (file_exist(buf))
		goto exist;

	sprintf(buf, "echo '%c:%s %s' >> /sys/kernel/debug/tracing/kprobe_events",
		ret ? 'r' : 'p', target, name);
	if (simple_exec(buf)) {
		pr_warn("failed to create kprobe: %s\n", target);
		return -1;
	}
	sprintf(buf, "/sys/kernel/debug/tracing/events/kprobes/%s/id",
		target);
exist:;
	int efd = open(buf, O_RDONLY, 0);
	if (efd < 0) {
		printf("failed to open event %s\n", name);
		return -1;
	}
	
	err = read(efd, buf, sizeof(buf));
	if (err < 0 || err >= sizeof(buf)) {
		printf("read from '%s' failed '%s'\n", target, strerror(errno));
		return -1;
	}

	close(efd);

	buf[err] = 0;
	id = atoi(buf);
	attr.config = id;

	efd = syscall(SYS_perf_event_open, &attr, -1, 0, -1, 0);
	if (efd < 0) {
		printf("event %d fd %d err %s\n", id, efd, strerror(errno));
		return -1;
	}
	ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);

	return 0;
}

#endif
