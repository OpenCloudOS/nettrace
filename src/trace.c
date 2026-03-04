// SPDX-License-Identifier: MulanPSL-2.0

#include <stdio.h>
#include <errno.h>

#include "utils/list.h"
#include "trace.h"
#include "analysis.h"
#include "dropreason.h"
#include "rstreason.h"

const char *cond_pre = "verlte() { [ \"$1\" = \"$2\" ] && echo 0 && return; "
		       "[ \"$1\" = \"$(/bin/echo -e \"$1\\n$2\" | sort -V | head -n1)\" ] "
		       "&& echo -1 && return; echo 1; }";

trace_context_t trace_ctx = {
	.mode = TRACE_MODE_TIMELINE,
};

extern trace_ops_t tracing_ops;

static bool trace_group_valid(trace_group_t *group)
{
	trace_list_t *trace_list;
	trace_group_t *pos;

	if (!list_empty(&group->traces)) {
		list_for_each_entry(trace_list, &group->traces, list)
			if (!trace_is_invalid(trace_list->trace))
				return true;
		return false;
	}

	if (!list_empty(&group->children)) {
		list_for_each_entry(pos, &group->children, list)
			if (trace_group_valid(pos))
				return true;
	}
	return false;
}

static void __print_trace_group(trace_group_t *group, int level)
{
	char prefix[32] = {}, buf[32], *name;
	trace_list_t *trace_list;
	trace_group_t *pos;
	trace_t *trace;
	u32 status;
	int i = 0;

	for (; i< level; i++)
		prefix[i] = '\t';

	if (!trace_group_valid(group))
		return;

	pr_info("%s"PFMT_EMPH"%s"PFMT_END": %s\n", prefix, group->name,
		group->desc);
	if (!list_empty(&group->traces))
		goto print_trace;

	if (list_empty(&group->children))
		return;

	list_for_each_entry(pos, &group->children, list)
		__print_trace_group(pos, level + 1);

	return;
print_trace:
	list_for_each_entry(trace_list, &group->traces, list) {
		trace = trace_list->trace;
		status = trace->status;

		if (trace_is_invalid(trace))
			continue;

		buf[0] = '\0';
		if (status & TRACE_LOADED)
			sprintf_end(buf, ",%s", PFMT_EMPH_STR("loaded"));
		if (status & TRACE_INVALID)
			sprintf_end(buf, ",%s", PFMT_WARN_STR("invalid"));

		if (trace->monitor)
			sprintf_end(buf, ",%s", PFMT_WARN_STR("monitor"));

		/* skip the prefix of __trace_ */
		name = trace->prog + TRACE_PREFIX_LEN - 1;
		if (buf[0]) {
			buf[0] = ' ';
			pr_info("%s  - %s:%s\n",  prefix, name, buf);
		} else {
			pr_info("%s  - %s\n",  prefix, name);
		}
	}
}

void trace_show(trace_group_t *group)
{
	__print_trace_group(group, 0);
}

static trace_group_t *_search_trace_group(char *name, trace_group_t *group)
{
	trace_group_t *pos, *tmp;

	if (strcmp(group->name, name) == 0)
		return group;

	list_for_each_entry(pos, &group->children, list) {
		tmp = _search_trace_group(name, pos);
		if (tmp)
			return tmp;
	}

	return NULL;
}

trace_group_t *search_trace_group(char *name)
{
	return _search_trace_group(name, &root_group);
}

trace_t *search_trace_enabled(char *name)
{
	trace_t *t;

	trace_for_each(t) {
		if (strcmp(t->name, name) == 0)
			return t;
	}
	return NULL;
}

enum trace_parse {
	TRACE_PARSE_ENABLE,
	TRACE_PARSE_STACK,
	TRACE_PARSE_MATCHER,
	TRACE_PARSE_EXCLUDE,
	TRACE_PARSE_CFREE,
};

static int trace_set_target(trace_t *t, enum trace_parse target)
{
	int err = 0;

	switch (target) {
	case TRACE_PARSE_ENABLE:
		trace_set_enable(t);
		break;
	case TRACE_PARSE_STACK:
		err = trace_set_stack(t);
		break;
	case TRACE_PARSE_MATCHER:
		trace_set_flag(t->index, FUNC_FLAG_MATCHER);
		break;
	case TRACE_PARSE_EXCLUDE:
		trace_set_invalid_reason(t, "exclude");
		break;
	case TRACE_PARSE_CFREE:
		trace_set_flag(t->index, FUNC_FLAG_CFREE);
		t->status |= TRACE_CFREE;
		break;
	}

	return err;
}

int trace_enable(char *name, enum trace_parse target)
{
	bool found = false;
	int err = 0;
	trace_t *t;

	trace_for_each(t) {
		if (strcmp(t->name, name))
			continue;

		err = trace_set_target(t, target);
		if (err)
			return err;
		found = true;
	}
	if (!found)
		pr_err("trace not found: %s\n", name);
	return !found;
}

static int __trace_group_enable(trace_group_t *group, enum trace_parse target)
{
	trace_group_t *pos;
	trace_list_t *t;
	int err = 0;

	list_for_each_entry(pos, &group->children, list) {
		err = __trace_group_enable(pos, target);
		if (err)
			return err;
	}

	list_for_each_entry(t, &group->traces, list) {
		err = trace_set_target(t->trace, target);
		if (err)
			return err;
	}

	return 0;
}

/* enable all traces in the group of 'name' */
int trace_group_enable(char *name, enum trace_parse target)
{
	trace_group_t *g = search_trace_group(name);

	if (!g)
		return trace_enable(name, target);

	return __trace_group_enable(g, target);
}

bool trace_analyzer_enabled(analyzer_t *analyzer)
{
	trace_t *t;

	trace_for_each(t) {
		if (TRACE_HAS_ANALYZER(t, free) && trace_is_enable(t))
			return true;
	}
	return false;
}

/* enable 'return value trace' for all function traces */
static void trace_all_set_ret()
{
	trace_t *trace;

	trace_for_each(trace)
	if (trace_is_func(trace))
		trace_set_ret(trace);
}

static bool trace_has_pkt_filter()
{
	pkt_args_t *pkt_args = &trace_ctx.bpf_args.pkt;

	return pkt_args->daddr || pkt_args->addr || pkt_args->saddr ||
	       pkt_args->saddr_v6[0] || pkt_args->daddr_v6[0] ||
	       pkt_args->addr_v6[0]|| pkt_args->sport ||
	       pkt_args->dport|| pkt_args->port||
	       pkt_args->l3_proto || pkt_args->l4_proto;
}

/* By default, don't allow to trace 'all' without any filter condition,
 * as it will cause performance problem.
 */
static int trace_check_force()
{
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	trace_args_t *args = &trace_ctx.args;

	if (args->drop || args->force || args->monitor || args->show_traces ||
	    args->rtt)
		return 0;

	if (trace_has_pkt_filter() || bpf_args->pid || bpf_args->first_rtt ||
	    bpf_args->last_rtt ||
	    (args->traces && strcmp(args->traces, "all") != 0) ||
	    args->count)
		return 0;

	return -1;
}

static int trace_parse_traces(char *traces, enum trace_parse target)
{
	char *tmp, *cur;

	if (!traces)
		return 0;

	tmp = calloc(strlen(traces) + 1, 1);
	strcpy(tmp, traces);
	cur = strtok(tmp, ",");
	while (cur) {
		if (trace_group_enable(cur, target)) {
			free(tmp);
			return -EINVAL;
		}
		cur = strtok(NULL, ",");
	}
	free(tmp);

	return 0;
}

static int parse_tcp_flasg(char *flags_str)
{
	u8 flags = 0;

	while (*flags_str != '\0') {
		switch (*flags_str) {
		case 'S':
			flags |= TCP_FLAGS_SYN;
			break;
		case 'A':
			flags |= TCP_FLAGS_ACK;
			break;
		case 'P':
			flags |= TCP_FLAGS_PSH;
			break;
		case 'R':
			flags |= TCP_FLAGS_RST;
			break;
		case 'F':
			flags |= TCP_FLAGS_FIN;
			break;
		default:
			return -EINVAL;
		}
		flags_str++;
	}
	return flags;
}

static void trace_check_sock_skb()
{
	int mode_mask = 1 << trace_ctx.mode;
	bool require_skb, require_sk;
	trace_t *trace;

	require_skb = mode_mask & TRACE_MODE_SKB_REQUIRE_MASK;
	require_sk = mode_mask & TRACE_MODE_SOCK_REQUIRE_MASK;

	/* disable traces that don't support sk in SOCK_MODE, and disable
	 * traces that don't support skb in !(SOCK_MODE || MONITOR_MODE).
	 */
	trace_for_each_cond(trace, (require_skb && trace->skb < 0) ||
				   (require_sk && trace->sk < 0))
			trace_set_invalid_reason(trace, "sock or sk mode");
}

static void trace_prepare_pesudo(trace_args_t *args, bpf_args_t *bpf_args)
{
	if (args->rtt_detail) {
		args->traces = "tcp_ack_update_rtt";
		args->sock = true;
		args->rtt = false;
	}

	if (bpf_args->latency_summary)
		args->latency = true;
}

static void trace_enable_default()
{
	trace_t *trace;

	trace_for_each(trace) {
		if (trace->def)
			trace_set_enable(trace);
	}
}

static int trace_prepare_args()
{
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	trace_args_t *args = &trace_ctx.args;
	int err;

	trace_prepare_pesudo(args, bpf_args);

	if (args->basic + args->intel + args->drop + args->sock +
	    args->rtt + args->latency > 1) {
		pr_err("multi-mode specified!\n");
		goto err;
	}

#define ASSIGN_MODE(name, __mode) do {			\
	if (args->name)					\
		trace_ctx.mode = TRACE_MODE_##__mode;	\
} while (0)

	ASSIGN_MODE(basic, BASIC);
	ASSIGN_MODE(intel, DIAG);
	ASSIGN_MODE(sock, SOCK);
	ASSIGN_MODE(monitor, MONITOR);
	ASSIGN_MODE(drop, DROP);
	ASSIGN_MODE(rtt, RTT);
	ASSIGN_MODE(latency, LATENCY);

	trace_ctx.mode_mask = 1 << trace_ctx.mode;

	if (trace_ctx.mode == TRACE_MODE_LATENCY && bpf_args->func_stats) {
		pr_err("function stats is not supported in latency mode\n");
		goto err;
	}

	if (drop_reason_support()) {
		bpf_args->drop_reason = true;
		trace_ctx.drop_reason = true;
		get_drop_reason(1);
	}

	if (reset_reason_support()) {
		trace_ctx.reset_reason = true;
		get_reset_reason(1);
	}

	if (bpf_args->rate_limit && (trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
		pr_err("--rate-limit can't be used in timeline(default)/diag mode\n");
		goto err;
	}

	trace_ctx.bpf_data.__rate_limit = bpf_args->rate_limit;
	bpf_args->has_filter = trace_has_pkt_filter();

	if (args->latency_show && !mode_has_context()) {
		pr_err("--latency-show not supported in this mode\n");
		goto err;
	}

	if (args->min_latency) {
		if (!(trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
			pr_err("--min-latency is not supported in this mode\n");
			goto err;
		}
		args->latency_show = true;
		bpf_args->latency_min = args->min_latency;
	}

	/* enable tcp_ack_update_rtt as monitor if rtt set */
	if (bpf_args->first_rtt || bpf_args->last_rtt) {
		bpf_args->first_rtt *= 1000;
		bpf_args->last_rtt *= 1000;
		trace_tcp_ack_update_rtt.monitor = 2;
	}

	if (args->netns_current) {
		bpf_args->netns = file_inode("/proc/self/ns/net");
		pr_debug("current netns inode is: %u\n", bpf_args->netns);
	}

	bpf_args->trace_mode = 1 << trace_ctx.mode;
	trace_ctx.detail = bpf_args->detail;
	bpf_args->max_event = args->count;
	trace_ctx.skip_last = !bpf_args->latency_free;

	if (args->pkt_len) {
		u32 len_1, len_2;
		char buf[32];

		if (sscanf(args->pkt_len, "%u-%u%s", &len_1, &len_2,
			buf) == 2) {
			bpf_args->pkt.pkt_len_1 = len_1;
			bpf_args->pkt.pkt_len_2 = len_2;
		} else if (sscanf(args->pkt_len, "%u%s", &len_1,
			buf) == 1) {
			bpf_args->pkt.pkt_len_1 = len_1;
			bpf_args->pkt.pkt_len_2 = len_1;
		} else {
			pr_err("--pkt_len: invalid format. valid format: "
			       "10 or 10-20\n");
			goto err;
		}
	}

	if (args->tcp_flags) {
		err = parse_tcp_flasg(args->tcp_flags);
		if (err < 0) {
			pr_err("--tcp-flags: invalid char, valid chars "
			       "are: SAPR\n");
			goto err;
		}
		bpf_args->pkt.tcp_flags = err;
	}

	if (trace_check_force()) {
		pr_err("\tdon't allow to trace 'all' without any filter condition,\n"
		       "\tas it will cause performance problem.\n\n"
		       "\t** You can use '--force' to skip this check **\n");
		goto err;
	}

	return 0;
err:
	return -1;
}

static void trace_exec_cond()
{
	trace_t *trace;

	trace_for_each(trace) {
		if (trace->cond && execf(NULL, "%s; %s", cond_pre,
					 trace->cond))
			trace_set_invalid_reason(trace, "cond");
	}
}

static void trace_prepare_status()
{
	u32 mode = trace_ctx.mode_mask;
	trace_t *trace;

	trace_for_each(trace) {
		if (TRACE_HAS_ANALYZER(trace, free) || TRACE_HAS_ANALYZER(trace, drop))
			trace_set_flag(trace->index, FUNC_FLAG_FREE);

		/* in the monitor mode, perfer to trace skb, then sk */
		if (!trace->skb || (mode & (TRACE_MODE_SOCK_MASK | TRACE_MODE_RTT_MASK))) {
			if (trace->sk)
				trace_set_flag(trace->index, FUNC_FLAG_SK);
		}
	}
}

static int trace_prepare_mode(trace_args_t *args)
{	trace_t *trace;

	switch (trace_ctx.mode) {
	case TRACE_MODE_DIAG:
		trace_all_set_ret();
	case TRACE_MODE_TIMELINE:
		if (!trace_ctx.args.traces_noclone) {
			/* enable skb clone trace */
			trace_set_ret(&trace_skb_clone);
		}
		break;
	case TRACE_MODE_LATENCY:
		trace_set_invalid_reason(&trace_skb_clone, "latency");
		break;
	case TRACE_MODE_DROP:
		if (!trace_ctx.drop_reason)
			pr_warn("skb drop reason is not support by your kernel"
				", drop reason will not be printed\n");
		if (args->drop_stack) {
			if (trace_set_stack(&trace_kfree_skb))
				goto err;
		}
		trace_set_enable(&trace_kfree_skb);
	case TRACE_MODE_BASIC:
	case TRACE_MODE_SOCK:
		break;
	case TRACE_MODE_MONITOR:
		trace_for_each(trace) {
			if (!trace->monitor) {
				trace_set_invalid_reason(trace, "monitor");
				continue;
			}
			if (trace_is_func(trace) && trace->monitor == TRACE_MONITOR_EXIT)
				trace_set_retonly(trace);
		}
		break;
	case TRACE_MODE_RTT:
		trace_set_enable(&trace_tcp_ack_update_rtt);
		break;
	default:
		pr_err("mode not supported!\n");
		goto err;
	}

	if (!args->ret)
		return 0;

	switch (trace_ctx.mode) {
	case TRACE_MODE_BASIC:
		pr_err("return value trace is only supported on "
		       "default and 'diag' mode\n");
		goto err;
	case TRACE_MODE_TIMELINE:
		trace_all_set_ret();
		break;
	case TRACE_MODE_DIAG:
	default:
		break;
	}
	return 0;

err:
	return -EINVAL;
}

static int trace_prepare_traces()
{
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	trace_args_t *args = &trace_ctx.args;
	char *traces_stack = args->traces_stack;
	char *traces = args->traces;
	bool fix_trace;

	if ((1 << trace_ctx.mode) & TRACE_MODE_BPF_CTX_MASK)
		trace_group_enable("life", TRACE_PARSE_ENABLE);
	trace_exec_cond();

	trace_prepare_status();

	fix_trace = args->drop || args->rtt;
	if (!traces) {
		if (!fix_trace)
			trace_enable_default();
	} else if (strcmp(traces, "?") == 0) {
		args->show_traces = true;
		traces = "all";
	} else {
		if (fix_trace) {
			pr_err("can't specify traces in this mode!\n");
			return -EINVAL;
		}
		trace_parse_traces(traces, TRACE_PARSE_ENABLE);
	}

	trace_parse_traces(args->trace_exclude, TRACE_PARSE_EXCLUDE);
	if (args->trace_matcher) {
		if (!(trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
			pr_err("--trace-matcher not supported in this mode\n");
			return -EINVAL;
		}
		trace_parse_traces(args->trace_matcher, TRACE_PARSE_MATCHER);
		bpf_args->match_mode = true;
	}

	if (args->trace_free) {
		if (!(trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
			pr_err("--trace_free not supported in this mode\n");
			return -EINVAL;
		}
		trace_parse_traces(args->trace_free, TRACE_PARSE_CFREE);
	}

	trace_parse_traces(traces_stack, TRACE_PARSE_STACK);
	if (trace_prepare_mode(args))
		return -EINVAL;

	if (trace_ctx.ops->prepare_traces)
		trace_ctx.ops->prepare_traces();

	/* This should be called after trace_ctx.ops->prepare_traces, as it
	 * will setup the skb or sk index for the traces.
	 */
	if (!fix_trace)
		trace_check_sock_skb();

	return 0;
}

static void trace_print_enabled()
{
	trace_t *trace;
	char *fmt;

	pr_verb("following traces are enabled and valid:\n");
	trace_for_each(trace) {
		if (!trace_is_usable(trace))
			continue;

		if (trace_is_func(trace)) {
			if (trace_is_ret(trace))
				fmt = "fentry/fexit";
			else if (trace_is_retonly(trace))
				fmt = "fexit";
			else
				fmt = "fentry";
		} else {
			fmt = "tp_btf";
		}
		pr_verb("\t%s: %s, prog: %s, status: 0x%x, flags: 0x%x\n", fmt, trace->name,
			trace->prog, trace->status, trace_get_flags(trace->index));
	}
}

static void trace_prepare_ops()
{
	if (trace_ctx.bpf_args.func_stats) {
		trace_ctx.ops->raw_poll = func_stats_poll_handler;
		return;
	}

	switch (trace_ctx.mode) {
	case TRACE_MODE_BASIC:
	case TRACE_MODE_DROP:
	case TRACE_MODE_MONITOR:
		trace_ctx.ops->trace_poll = basic_poll_handler;
		break;
	case TRACE_MODE_SOCK:
		trace_ctx.ops->trace_poll = basic_poll_handler;
		break;
	case TRACE_MODE_DIAG:
	case TRACE_MODE_TIMELINE:
		trace_ctx.ops->trace_poll = ctx_poll_handler;
		break;
	case TRACE_MODE_LATENCY:
		if (trace_ctx.bpf_args.latency_summary)
			trace_ctx.ops->raw_poll = stats_poll_handler;
		else
			trace_ctx.ops->trace_poll = latency_poll_handler;
		break;
	case TRACE_MODE_RTT:
		trace_ctx.ops->raw_poll = stats_poll_handler;
	default:
		break;
	}
}

static int trace_sys_check(void)
{
	if (!debugfs_mounted()) {
		pr_err("debugfs is not mounted! Please mount it with the "
		       "command: mount -t debugfs debugfs "
		       "/sys/kernel/debug\n");
		return -EOPNOTSUPP;
	}

	if (!file_exist("/sys/kernel/btf/vmlinux") && !trace_ctx.args.btf_path) {
		pr_err("BTF is not support by your kernel, please use the legancy version\n");
		return -EOPNOTSUPP;
	}

	if (!kernel_has_config("DEBUG_INFO_BTF_MODULES")) {
		pr_warn("DEBUG_INFO_BTF_MODULES not enabled, some infomation, "
			"such as nf_tables, maybe incorrect\n");
	}

	return 0;
}

static int trace_prepare()
{
	int err;

	err = trace_prepare_args();
	if (err)
		goto err;

	if (!tracing_ops.trace_supported()) {
		pr_err("tracing (fentry/fexit) is not supported!\n");
		err = -EINVAL;
		goto err;
	}
	set_trace_ops(&tracing_ops);

	err = trace_prepare_traces();
	if (err)
		goto err;

	if (trace_ctx.args.show_traces) {
		trace_show(&root_group);
		exit(0);
	}
	trace_print_enabled();
	trace_prepare_ops();

	return 0;
err:
	return err;
}

int trace_pre_load()
{
	struct bpf_program *prog;
	trace_t *trace;

	if (geteuid() != 0) {
		pr_err("Please run as root!\n");
		return -EPERM;
	}

	/* disable all programs that is not enabled or invalid */
	trace_for_each(trace) {
		if (!trace->custom)
			continue;

		bool autoload = !trace_is_invalid(trace) && trace_is_enable(trace);

		if (autoload && !trace_is_retonly(trace))
			goto check_ret;

		prog = bpf_pbn(trace_ctx.obj, trace->prog);
		if (!prog) {
			pr_verb("prog: %s not founded\n", trace->prog);
			continue;
		}
		bpf_program__set_autoload(prog, false);
		pr_debug("prog: %s is made no-autoload\n", trace->prog);

check_ret:
		if (!trace_is_func(trace) || (trace_is_ret_any(trace) && autoload))
			continue;

		prog = bpf_pbn(trace_ctx.obj, trace->ret_prog);
		if (!prog) {
			pr_verb("prog: %s not founded\n", trace->ret_prog);
			continue;
		}
		bpf_program__set_autoload(prog, false);
		pr_debug("ret prog: %s is made no-autoload\n", trace->prog);
	}

	prog = bpf_pbn(trace_ctx.obj, "nt__default");
	if (prog) {
		bpf_program__set_autoload(prog, false);
		bpf_program__set_autoattach(prog, false);
	}
	prog = bpf_pbn(trace_ctx.obj, "nt_ret__default");
	if (prog) {
		bpf_program__set_autoload(prog, false);
		bpf_program__set_autoattach(prog, false);
	}
	prog = bpf_pbn(trace_ctx.obj, "nt__default_tp");
	if (prog) {
		bpf_program__set_autoload(prog, false);
		bpf_program__set_autoattach(prog, false);
	}

	return 0;
}

static inline int ringbuf_handler_wrap(void *ctx, void *data, size_t size)
{
	if (trace_stopped())
		return 0;

	trace_ctx.ops->trace_poll(ctx, data, (u32)size);
	return 0;
}

static int log_ringbuf_handler(void *ctx, void *data, size_t size)
{
	const log_event_t *log = data;

	(void)ctx;
	trace_stop();

	if (size < sizeof(*log)) {
		pr_err("bpf log event truncated (size=%zu)\n", size);
		exit(EXIT_FAILURE);
	}

	if (log->msg[0])
		pr_err("BPF error: %s\n", log->msg);
	else
		pr_err("BPF error: code=%u\n", log->code);

	exit(EXIT_FAILURE);
}

static int poll_timeout(int err)
{
	if (trace_ctx.stop)
		return 1;

	if (err == 0 && trace_ctx.args.count) {
		if (trace_ctx.args.count <= get_bpf_data()->event_count) {
			usleep(200000);
			return 1;
		}

		return 0;
	}
	return 0;
}

int trace_poll()
{
	struct ring_buffer *rb;
	int err, map_fd, log_fd;

	if (trace_ctx.ops->raw_poll) {
		trace_ctx.ops->trace_ready();
		return trace_ctx.ops->raw_poll();
	}

	map_fd = bpf_object__find_map_fd_by_name(trace_ctx.obj, "m_ringbuf");
	if (!map_fd)
		return -1;

	rb = ring_buffer__new(map_fd, ringbuf_handler_wrap, NULL, NULL);

	err = libbpf_get_error(rb);
	if (err) {
		pr_err("failed to setup ring_buffer: %d\n", err);
		return err;
	}

	log_fd = bpf_object__find_map_fd_by_name(trace_ctx.obj, "m_log_ringbuf");
	if (!log_fd) {
		pr_err("failed to find BPF map m_log_ringbuf\n");
		ring_buffer__free(rb);
		return -1;
	}

	err = ring_buffer__add(rb, log_fd, log_ringbuf_handler, NULL);
	if (err) {
		pr_err("failed to add log ring_buffer: %d\n", err);
		ring_buffer__free(rb);
		return err;
	}

	trace_ctx.ops->trace_ready();
	while ((err = ring_buffer__poll(rb, 1000)) >= 0) {
		if (poll_timeout(err))
			break;
	}
	return 0;
}

int trace_main()
{
	int err;

	err = trace_sys_check();
	if (err)
		return err;

	err = trace_prepare();
	if (err)
		return err;

	if (liberate_l())
		pr_warn("failed to set rlimit\n");

	if (trace_ctx.ops->trace_open) {
		err = trace_ctx.ops->trace_open();
		if (err)
			return err;
	}

	err = trace_pre_load();
	if (err) {
		pr_err("failed to prepare load\n");
		return err;
	}

	err = trace_ctx.ops->trace_load();
	if (err) {
		pr_err("failed to load bpf\n");
		return err;
	}

	pr_debug("begin to attach eBPF program...\n");
	err = trace_ctx.ops->trace_attach();
	if (err) {
		trace_ctx.ops->trace_close();
		return err;
	}
	pr_debug("eBPF program attached successfully\n");

	return 0;
}
