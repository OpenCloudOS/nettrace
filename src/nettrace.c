// SPDX-License-Identifier: MulanPSL-2.0

#include <arg_parse.h>
#include <common_args.h>

#include "nettrace.h"
#include "trace.h"

arg_config_t config = {
	.name = "nettrace",
	.summary = "a tool to trace skb in kernel and diagnose network problem",
	.desc = "",
};

static void do_parse_args(int argc, char *argv[])
{
	trace_args_t *trace_args = &trace_ctx.args;
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	pkt_args_t *pkt_args = &bpf_args->pkt;
	bool show_log = false, debug = false;
	int proto_l = 0;
	u16 proto;

	option_item_t opts[] = {
		COMMON_PROG_ARGS(pkt_args),
		{
			.lname = "pid", .type = OPTION_U32,
			.dest = &bpf_args->pid, .set = &bpf_args->enable_pid,
			.desc = "filter by current process id(pid)",
		},
		{
			.lname = "trace", .sname = 't',
			.dest = &trace_args->traces,
			.desc = "enable trace group or trace",
		},
		{
			.lname = "ret", .dest = &trace_args->ret,
			.type = OPTION_BOOL,
			.desc = "show function return value",
		},
		{
			.lname = "detail", .dest = &bpf_args->detail,
			.type = OPTION_BOOL,
			.desc = "show extern packet info, such as pid, ifname, etc",
		},
		{
			.lname = "basic", .dest = &trace_args->basic,
			.type = OPTION_BOOL,
			.desc = "use 'basic' trace mode, don't trace skb's life",
		},
		{
			.lname = "diag", .dest = &trace_args->intel,
			.type = OPTION_BOOL,
			.desc = "enable 'diagnose' mode",
		},
		{
			.lname = "diag-quiet", .dest = &trace_args->intel_quiet,
			.type = OPTION_BOOL,
			.desc = "only print abnormal packet",
		},
		{
			.lname = "diag-keep", .dest = &trace_args->intel_keep,
			.type = OPTION_BOOL,
			.desc = "don't quit when abnormal packet found",
		},
		{
			.lname = "hooks", .dest = &bpf_args->hooks,
			.type = OPTION_BOOL,
			.desc = "print netfilter hooks if dropping by netfilter",
		},
		{
			.lname = "drop", .dest = &trace_args->drop,
			.type = OPTION_BOOL,
			.desc = "skb drop monitor mode, for replace of 'droptrace'",
		},
		{ .type = OPTION_BLANK },
		{
			.sname = 'v', .dest = &show_log,
			.type = OPTION_BOOL,
			.desc = "show log information",
		},
		{
			.lname = "debug", .dest = &debug,
			.type = OPTION_BOOL,
			.desc = "show debug information",
		},
		{
			.lname = "help",
			.sname = 'h',
			.type = OPTION_HELP,
			.desc = "show help information",
		},
	};

	if (parse_args(argc, argv, &config, opts, ARRAY_SIZE(opts)))
		goto err;

	if (show_log)
		set_log_level(1);

	if (!debug)
		/* turn off warning of libbpf */
		libbpf_set_print(NULL);
	else
		set_log_level(2);

	switch (proto_l) {
	case 3:
		pkt_args->enable_l3_proto = true;
		pkt_args->l3_proto = proto;
		break;
	case 4:
		pkt_args->enable_l4_proto = true;
		pkt_args->l4_proto = proto;
		break;
	default:
		break;
	}

	return;
err:
	exit(-EINVAL);
}

int main(int argc, char *argv[])
{
	trace_ops_t *ops = &probe_ops;

	init_trace_group();
	do_parse_args(argc, argv);
	if (trace_prepare())
		goto err;

	set_trace_ops(&probe_ops);
	if (trace_bpf_load()) {
		pr_err("failed to load kprobe-based bpf\n");
		goto err;
	}
	pr_info("begin trace...\n");
	trace_poll(trace_ctx);
	pr_info("end trace...\n");
	return 0;
err:
	return -1;
}
