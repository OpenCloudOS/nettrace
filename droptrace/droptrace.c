// SPDX-License-Identifier: MulanPSL-2.0

#include <getopt.h>
#include <stdlib.h>
#include <asm-generic/int-ll64.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/bpf.h>

#include <net_utils.h>
#include <bpf_utils.h>
#include <arg_parse.h>
#include <pkt_utils.h>

#include "./progs/shared.h"
#include "progs/probe.skel.h"
#include "progs/trace.skel.h"
#include "reasons.h"
#include "parse_sym.h"

#define MAX_OUTPUT_LENGTH	256
#define ROOT_PIN_PATH		"/sys/fs/bpf/droptrace/"
#define SNMP_PIN_PATH		ROOT_PIN_PATH"snmp"
#define TRACE_PIN_PATH		ROOT_PIN_PATH"trace"

typedef typeof(*((struct trace *)0)->rodata) bpf_args_t;

u32 snmp_reasons[SKB_DROP_REASON_MAX];

static bool snmp_mode	= false,
	    ts_show	= false,
	    raw_sym	= false;
static char buf[1024];
static arg_config_t prog_config = {
	.name = "droptrace",
	.summary = "a tool to monitor the packet dropped by kernel",
	.desc = ""
};

static void print_drop_packet(void *ctx, int cpu, void *data, __u32 size)
{
	char ts_str[32], raw_sym_desc[20];
	const char *reason_str;
	struct sym_result *sym;
	char *sym_desc = NULL;
	event_t *e = data;
	u16 reason;

	reason = e->reason;
	if (reason >= SKB_DROP_REASON_MAX || reason <= 0) {
		printf("unknow drop reason: %d", reason);
		reason = SKB_DROP_REASON_NOT_SPECIFIED;
	}
	reason_str = drop_reasons[reason];
	if (!reason_str)
		printf("invalid reason found:%d\n", reason);
	if (!raw_sym) {
		sym = parse_sym(e->location);
		sym_desc = sym->desc;
	} else {
		sym_desc = raw_sym_desc;
		sprintf(sym_desc, "0x%llx", e->location);
	}

	base_print_packet(buf, &e->pkt);
	printf("%s reason:%s %s\n", buf, reason_str, sym_desc);
}

static int do_drop_monitor(int map_fd)
{
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	struct droptrace *obj;
	int ret;

	pb_opts.sample_cb = print_drop_packet;
	pb = perf_buffer__new(map_fd, 8, &pb_opts);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return -1;
	}

	while ((ret = perf_buffer__poll(pb, 1000)) >= 0) {
	}
	return 0;
}

static int do_stat_stop()
{
	if (access(SNMP_PIN_PATH, F_OK)) {
		printf("not loaded\n");
		goto err;
	}
	unlink(TRACE_PIN_PATH);
	unlink(SNMP_PIN_PATH);
	printf("stat stop successful!\n");
	return 0;

err:
	return -1;
}

static int parse_opts(int argc, char *argv[], bpf_args_t *args)
{
	bool stat_stop = false;
	int proto_l = 0;
	u16 proto;

#define E(name) &(args->enable_##name)
#define R(name)	&(args->arg_##name)
	option_item_t opts[] = {
#include <common_args.h>
		{
			.lname = "reason",
			.sname = 'r',
			.dest = R(reason),
			.type = OPTION_U16,
			.set = E(reason),
			.desc = "filter drop reason",
		},
		{ .type = OPTION_BLANK },
		{
			.lname = "raw-sym",
			.dest = &raw_sym,
			.type = OPTION_BOOL,
			.desc = "show kernel symbol address (default false)"
		},
		{
			.lname = "stat",
			.dest = &snmp_mode,
			.type = OPTION_BOOL,
			.desc = "show drop statistics",
		},
		{
			.lname = "stat-stop",
			.dest = &stat_stop,
			.type = OPTION_BOOL,
			.desc = "stop drop statistics and remove the launched"
				" eBPF program",
		},
		{
			.lname = "limit",
			.sname = 'l',
			.dest = R(limit),
			.type = OPTION_U32,
			.set = E(limit),
			.desc = "set the max output pcaket per second, default"
				"unlimited",
		},
		{
			.lname = "limit-budget",
			.dest = R(limit_bucket),
			.type = OPTION_U32,
			.set = E(limit_bucket),
			.desc = "set the budget depth of the token used to limit"
				"output rate",
		},
		{
			.lname = "help",
			.sname = 'h',
			.type = OPTION_HELP,
			.desc = "show help information",
		},
	};

	if (parse_args(argc, argv, &prog_config, opts, ARRAY_SIZE(opts)))
		goto err;

	if (proto_l == 3) {
		*R(l3_proto) = proto;
		*E(l3_proto) = true;
	} else if (proto_l == 4) {
		*R(l4_proto) = proto;
		*E(l4_proto) = true;
	}

	if (stat_stop) {
		do_stat_stop();
		goto exit;
	}

	args->arg_snmp_mode = snmp_mode;
	return 0;
err:
	return -1;
exit:
	exit(0);
}

static void print_drop_stat(int fd)
{
	int key = 0, i = 1, count;

	if (bpf_map_lookup_elem(fd, &key, snmp_reasons)) {
		printf("failed to load data\n");
		return;
	}

	printf("packet statistics:\n");
	for (; i < SKB_DROP_REASON_MAX; i++) {
		count = snmp_reasons[i];
		printf("  %s: %d\n", drop_reasons[i], count);
	}
}

#define SKEL_OPS(ops, ...) ({				\
		trace ? trace__##ops (__VA_ARGS__) :	\
			probe__##ops (__VA_ARGS__);	\
	})
#define SKEL_OBJ_FD(type, name)				\
	bpf_##type##__fd(trace ? trace->type##s.name :	\
		       probe->type##s.name)

int main(int argc, char *argv[])
{
	bpf_args_t bpf_args = {};
	struct trace *trace;
	struct probe *probe;
	int map_fd;
	void *obj;

	if (parse_opts(argc, argv, &bpf_args))
		goto err;
	if (snmp_mode)
		goto do_snmp;

do_load:
	libbpf_set_print(NULL);
	trace = trace__open();
	probe = probe__open();
	*(bpf_args_t *)probe->rodata = bpf_args;
	*(bpf_args_t *)trace->rodata = bpf_args;

	if (trace__load(trace)) {
		trace__destroy(trace);
		trace = NULL;
		if (probe__load(probe)) {
			printf("failed to load program\n");
			goto err;
		}
	}
	obj = (void *)trace ?: (void *)probe;

	if (SKEL_OPS(attach, obj)) {
		printf("failed to attach kfree_skb\n");
		goto err;
	}

	if (snmp_mode)
		goto do_snmp_pin;

	do_drop_monitor(SKEL_OBJ_FD(map, m_event));
	SKEL_OPS(destroy, obj);
	return 0;

err:
	SKEL_OPS(destroy, obj);
	return -1;

do_snmp_pin:
	if (access(ROOT_PIN_PATH, F_OK) && mkdir(ROOT_PIN_PATH, 744)) {
		printf("failed to create bpf pin path\n");
		goto err;
	}
	if (bpf_obj_pin(SKEL_OBJ_FD(map, bss), SNMP_PIN_PATH)) {
		printf("failed to pin snmp map\n");
		goto err;
	}
	if (bpf_obj_pin(SKEL_OBJ_FD(link, trace_kfree_skb), TRACE_PIN_PATH)) {
		printf("failed to pin program (your kernel seems don't support "
		       "bpf_link)\n");
		unlink(SNMP_PIN_PATH);
		goto err;
	}
	trace__destroy(obj);

do_snmp:
	if (access(SNMP_PIN_PATH, F_OK))
		goto do_load;
	map_fd = bpf_obj_get(SNMP_PIN_PATH);
	if (map_fd < 0) {
		printf("failed to open snmp\n");
		return -1;
	}
	print_drop_stat(map_fd);
	return 0;
}
