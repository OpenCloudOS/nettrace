// SPDX-License-Identifier: MulanPSL-2.0

#include "common.h"
#include "progs/ntrace.skel.h"

const char *locations[] = {
	[LOCALTION_INGRESS] = "reason: INGRESS",
	[LOCALTION_EGRESS] = "reason: EGRESS",
	[LOCALTION_MARK] = "reason: MARK",
	[LOCALTION_ERR] = "reason: ERR",
};
static char pref_ingress[16], pref_egress[16];
static char *nic;
static char buf[1024];
static arg_config_t prog_config = {
	.name = "watch",
	.summary = "monitor ip packet that marked by 'mark'",
	.desc = "",
};

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	event_t *e = data;

	base_print_packet(buf, &e->pkt);
	printf("[%-8s] %s\n", locations[e->location], buf);
}

static void do_cleanup(int code)
{
	tc_detach(nic, pref_ingress, true);
	tc_detach(nic, pref_egress, false);
}

int main(int argc, char *argv[])
{
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	struct ntrace *obj;
	int ret;

	option_item_t opts[] = {
		{
			.sname = 'i', .dest = &nic, .type = OPTION_STRING,
			.required = true,
			.desc = "target nic, such as 'eth0'",
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

	if (!(obj = ntrace__open_and_load())) {
		printf("failed to open eBPF program\n");
		goto err;
	}

	if (tc_attach(BPF_PROG_FD(ntrace_entry), nic, pref_ingress,
		      true)) {
		printf("failed to attach entry eBPF program\n");
		goto err;
	}
	if (tc_attach(BPF_PROG_FD(ntrace_exit), nic, pref_egress,
		      false)) {
		printf("failed to attach exit eBPF program\n");
		goto egress_err;
	}

	signal(SIGINT, do_cleanup);
	perf_output(BPF_MAP_FD(m_event), print_bpf_output);
	return 0;
err:
	return -1;
egress_err:
	tc_detach(nic, pref_ingress, true);
	goto err;
}
