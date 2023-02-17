// SPDX-License-Identifier: MulanPSL-2.0
#include <common_args.h>

#include "common.h"
#include "progs/shared.h"
#include "progs/ntrace.skel.h"

static char tc_pref[16];
static char *nic;
static char buf[1024];
static arg_config_t prog_config = {
	.name = "mark",
	.summary = "mark ip packet with special tag",
	.desc = "",
};

static void do_cleanup(int code)
{
	tc_detach(nic, tc_pref, false);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	event_t *e = data;
	packet_t *pkt;

	pkt = &e->pkt;
	base_print_packet(buf, pkt);
	printf("%s\n", buf);
}

static int parse_opts(int argc, char *argv[], bpf_args_t *args)
{
	COMMON_PROG_ARGS_BEGIN()

	option_item_t opts[] = {
		COMMON_PROG_ARGS_DEFINE(&args->pkt),
		{ .type = OPTION_BLANK },
		{
			.sname = 'i', .dest = &nic, .type = OPTION_STRING,
			.required = true,
			.desc = "target nic, such as 'eth0'",
		},
		{
			.sname = 'o', .dest = &args->quiet,
			.type = OPTION_BOOL_REV,
			.desc = "output packet info that marked",
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
	
	COMMON_PROG_ARGS_END(&args->pkt)
	return 0;
err:
	return -1;
}

int main(int argc, char *argv[])
{
	struct perf_buffer_opts pb_opts = {};
	bpf_args_t bpf_args = {};
	struct perf_buffer *pb;
	struct bpf_link *link;
	struct ntrace *obj;
	char cmd[256];
	int ret, opt;

	if (parse_opts(argc, argv, &bpf_args))
		goto err;

	if (!(obj = ntrace__open())) {
		printf("failed to open eBPF program\n");
		goto err;
	}
 	obj->data->_bpf_args = bpf_args;

	if (ntrace__load(obj)) {
		printf("failed to load program\n");
		goto err;
	}

	if (!nic) {
		printf("-i is needed\n");
		goto err;
	}

	if (tc_attach(BPF_PROG_FD(ntrace_mark), nic, tc_pref, false))
		goto err;

	signal(SIGINT, do_cleanup);
	perf_output(BPF_MAP_FD(m_event), print_bpf_output);
	return 0;
err:
	return -1;
}
