// SPDX-License-Identifier: MulanPSL-2.0

#include <arpa/inet.h>

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
	bool show_log = false, debug = false, version = false;
	trace_args_t *trace_args = &trace_ctx.args;
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	pkt_args_t *pkt_args = &bpf_args->pkt;
	COMMON_PROG_ARGS_BEGIN()

	option_item_t opts[] = {
		COMMON_PROG_ARGS_DEFINE(pkt_args),
		{
			.lname = "netns",
			.dest = &bpf_args->netns,
			.type = OPTION_U32,
			.desc = "filter by net namespace inode",
		},
		{
			.lname = "netns-current",
			.dest = &trace_args->netns_current,
			.type = OPTION_BOOL,
			.desc = "filter by current net namespace",
		},
		{
			.lname = "pid", .type = OPTION_U32,
			.dest = &bpf_args->pid, .set = &bpf_args->enable_pid,
			.desc = "filter by current process id(pid)",
		},
		{
			.lname = "min-latency", .dest = &trace_args->min_latency,
			.type = OPTION_U32,
			.desc = "filter by the minial time to live of the skb in ms",
		},
		{
			.lname = "pkt-len", .dest = &trace_args->pkt_len,
			.type = OPTION_STRING,
			.desc = "filter by the IP packet length (include header) in byte",
		},
		{
			.lname = "tcp-flags", .dest = &trace_args->tcp_flags,
			.type = OPTION_STRING,
			.desc = "filter by TCP flags, such as: SAPR",
		},
		{ .type = OPTION_BLANK },
		{
			.lname = "trace", .sname = 't',
			.dest = &trace_args->traces,
			.desc = "enable trace group or trace. Some traces are "
				"disabled by default, use \"all\" to enable all",
		},
		{
			.lname = "force", .dest = &trace_args->force,
			.type = OPTION_BOOL,
			.desc = "skip some check and force load nettrace",
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
			.lname = "date", .dest = &trace_args->date,
			.type = OPTION_BOOL,
			.desc = "print timestamp in date-time format",
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
#ifdef BPF_FEAT_STACK_TRACE
		{
			.lname = "drop-stack", .dest = &trace_args->drop_stack,
			.type = OPTION_BOOL,
			.desc = "print the kernel function call stack of kfree_skb",
		},
#endif
		{
			.lname = "sock", .dest = &trace_args->sock,
			.type = OPTION_BOOL,
			.desc = "enable 'sock' mode",
		},
		{
			.lname = "monitor", .dest = &trace_args->monitor,
			.type = OPTION_BOOL,
			.desc = "enable 'monitor' mode",
		},
		{
			.lname = "pkt-fixed", .dest = &bpf_args->pkt_fixed,
			.type = OPTION_BOOL,
			.desc = "set this option if you are sure the target "
				"packet is not NATed to get better "
				"performance",
		},
		{
			.lname = "trace-stack", .dest = &trace_args->traces_stack,
			.type = OPTION_STRING,
			.desc = "print call stack for traces or group",
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
#ifdef BPF_DEBUG
		{
			.lname = "bpf-debug", .dest = &bpf_args->bpf_debug,
			.type = OPTION_BOOL,
			.desc = "show bpf debug information",
		},
#endif
		{
			.lname = "help",
			.sname = 'h',
			.type = OPTION_HELP,
			.desc = "show help information",
		},
		{
			.lname = "version", .dest = &version,
			.sname = 'V',
			.type = OPTION_BOOL,
			.desc = "show nettrace version",
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

	if (version) {
		pr_version();
		exit(0);
	}

	COMMON_PROG_ARGS_END(pkt_args)

	return;
err:
	exit(-EINVAL);
}

static void do_exit(int code)
{
	static bool is_exited = false;

	if (is_exited)
		return;

	is_exited = true;
	pr_info("end trace...\n");
	pr_debug("begin destory BPF skel...\n");
	trace_ctx.ops->trace_close();
	pr_debug("BPF skel is destroied\n");
}

int main(int argc, char *argv[])
{
	init_trace_group();
	do_parse_args(argc, argv);

	if (trace_prepare())
		goto err;

	if (trace_bpf_load_and_attach()) {
		pr_err("failed to load kprobe-based bpf\n");
		goto err;
	}

	signal(SIGTERM, do_exit);
	signal(SIGINT, do_exit);

	pr_info("begin trace...\n");
	trace_poll(trace_ctx);
	do_exit(0);
	return 0;
err:
	return -1;
}
