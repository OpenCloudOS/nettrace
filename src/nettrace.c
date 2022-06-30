
#include <arg_parse.h>

#include "nettrace.h"
#include "trace.h"

arg_config_t config = {
	.name = "nettrace",
	.summary = "a tool to trace skb in kernel",
	.desc = "",
};

static void do_parse_args(int argc, char *argv[])
{
	trace_args_t *trace_args = &trace_ctx.args;
	bool show_log = false, debug = false;
	int proto_l = 0;
	u16 proto;

#define E(name) &(trace_ctx.bpf_args.enable_##name)
#define R(name)	&(trace_ctx.bpf_args.arg_##name)
	option_item_t opts[] = {
#include <common_args.h>
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
			.lname = "detail", .dest = R(detail),
			.type = OPTION_BOOL,
			.desc = "show extern packet info, such as pid, ifname, etc",
		},
		{
			.lname = "timeline", .dest = &trace_args->timeline,
			.type = OPTION_BOOL,
			.desc = "enable 'timeline' mode",
		},
		{
			.lname = "intel", .dest = &trace_args->intel,
			.type = OPTION_BOOL,
			.desc = "enable 'intel' mode",
		},
		{
			.lname = "intel-quiet", .dest = &trace_args->intel_quiet,
			.type = OPTION_BOOL,
			.desc = "only print abnormal packet",
		},
		{
			.lname = "intel-keep", .dest = &trace_args->intel_keep,
			.type = OPTION_BOOL,
			.desc = "don't quit when abnormal packet found",
		},
		{
			.lname = "hooks", .dest = R(hooks),
			.type = OPTION_BOOL,
			.desc = "print netfilter hooks if dropping by netfilter",
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
	if (debug)
		set_log_level(2);
	else
		/* turn off warning of libbpf */
		libbpf_set_print(NULL);

#define S_L(level)				\
	do {					\
		*R(l##level##_proto) = proto;	\
		*E(l##level##_proto) = true;	\
	} while (0)
	if (proto_l == 3)
		S_L(3);
	else if (proto_l == 4)
		S_L(4);

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
