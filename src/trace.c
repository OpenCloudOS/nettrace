// SPDX-License-Identifier: MulanPSL-2.0

#include <stdio.h>
#include <list.h>

#include <parse_sym.h>

#include "nettrace.h"
#include "trace.h"
#include "analysis.h"
#include "dropreason.h"

const char *cond_pre = "verlte() { [ \"$1\" = \"$2\" ] && echo 0 && return; "
		       "[ \"$1\" = \"$(/bin/echo -e \"$1\\n$2\" | sort -V | head -n1)\" ] "
		       "&& echo -1 && return; echo 1; }";

trace_context_t trace_ctx = {
	.mode = TRACE_MODE_TIMELINE,
};

extern trace_ops_t tracing_ops;
extern trace_ops_t probe_ops;
trace_ops_t *trace_ops_all[] = { &tracing_ops, &probe_ops };

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

#if 1
		if (trace_is_invalid(trace))
			continue;
#endif

		buf[0] = '\0';
		if (status & TRACE_LOADED)
			sprintf_end(buf, ",%s", PFMT_EMPH_STR("loaded"));
#if 0
		if (trace_is_enable(trace))
			sprintf_end(buf, ",%s", PFMT_EMPH_STR("enabled"));
#endif
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

int trace_enable(char *name, int target)
{
	bool found = false;
	int err = 0;
	trace_t *t;

	trace_for_each(t) {
		if (strcmp(t->name, name))
			continue;
		switch (target) {
		case 1:
			trace_set_enable(t);
			break;
		case 2:
			err = trace_set_stack(t);
			break;
		}
		if (err)
			return err;
		found = true;
	}
	if (!found)
		pr_err("trace not found: %s\n", name);
	return !found;
}

static int __trace_group_enable(trace_group_t *group, int target)
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
		switch (target) {
		case 1:
			trace_set_enable(t->trace);
			break;
		case 2:
			err = trace_set_stack(t->trace);
			break;
		}
		if (err)
			return err;
	}

	return 0;
}

/* enable all traces in the group of 'name' */
int trace_group_enable(char *name, int target)
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

static bool trace_has_end()
{
	return TRACE_ANALYZER_ENABLED(drop) || TRACE_ANALYZER_ENABLED(free);
}

/* enable 'return value trace' for all function traces */
static void trace_all_set_ret()
{
	trace_t *trace;

	trace_for_each(trace)
	if (trace_is_func(trace))
		trace_set_ret(trace);
}

/* By default, don't allow to trace 'all' without any filter condition,
 * as it will cause performance problem.
 */
static int trace_check_force()
{
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	pkt_args_t *pkt_args = &bpf_args->pkt;
	trace_args_t *args = &trace_ctx.args;

	if (args->drop || args->force || args->monitor || args->show_traces)
		return 0;

	if (ARGS_ENABLED(bpf_args, pid) || ARGS_ENABLED(pkt_args, saddr) ||
	    ARGS_ENABLED(pkt_args, daddr) || ARGS_ENABLED(pkt_args, addr) ||
	    ARGS_ENABLED(pkt_args, saddr_v6) || ARGS_ENABLED(pkt_args, daddr_v6) ||
	    ARGS_ENABLED(pkt_args, addr_v6)|| ARGS_ENABLED(pkt_args, sport) ||
	    ARGS_ENABLED(pkt_args, dport)|| ARGS_ENABLED(pkt_args, port)||
	    ARGS_ENABLED(pkt_args, l3_proto) || ARGS_ENABLED(pkt_args, l4_proto))
		return 0;

	return -1;
}

static int trace_prepare_args()
{
	trace_t *drop_trace = search_trace_enabled("kfree_skb");
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	trace_args_t *args = &trace_ctx.args;
	char *traces_stack = args->traces_stack;
	char *traces = args->traces;
	trace_t *trace;
	char *tmp, *cur;

	if (args->basic + args->intel + args->drop + args->sock > 1) {
		pr_err("multi-mode specified!\n");
		goto err;
	}

	if (args->basic)
		trace_ctx.mode = TRACE_MODE_BASIC;

	if (args->intel)
		trace_ctx.mode = TRACE_MODE_DIAG;

	if (args->sock)
		trace_ctx.mode = TRACE_MODE_SOCK;

	if (args->monitor)
		trace_ctx.mode = TRACE_MODE_MONITOR;

	if (args->drop_stack) {
		if (trace_set_stack(drop_trace))
			goto err;
	}

	if (args->drop) {
		trace_ctx.mode = TRACE_MODE_DROP;
		trace_set_enable(drop_trace);
		goto skip_trace;
	}

	if (traces_stack) {
		tmp = calloc(strlen(traces_stack) + 1, 1);
		strcpy(tmp, traces_stack);
		cur = strtok(tmp, ",");
		while (cur) {
			if (trace_group_enable(cur, 2)) {
				free(tmp);
				goto err;
			}
			cur = strtok(NULL, ",");
		}
		free(tmp);
	}

	if (!traces) {
		trace_for_each(trace)
			if (trace->def)
				trace_set_enable(trace);
		goto skip_trace;
	}

	if (strcmp(traces, "?") == 0) {
		args->show_traces = true;
		traces = "all";
	}

	tmp = calloc(strlen(traces) + 1, 1);
	strcpy(tmp, traces);
	cur = strtok(tmp, ",");
	while (cur) {
		if (trace_group_enable(cur, 1)) {
			free(tmp);
			goto err;
		}
		cur = strtok(NULL, ",");
	}
	free(tmp);

skip_trace:
	if (!debugfs_mounted()) {
		pr_err("debugfs is not mounted! Please mount it with the "
		       "command: mount -t debugfs debugfs "
		       "/sys/kernel/debug\n");
		goto err;
	}

	if (drop_reason_support()) {
		bpf_args->drop_reason = true;
		trace_ctx.drop_reason = true;
		get_drop_reason(1);
	}

	switch (trace_ctx.mode) {
	case TRACE_MODE_DIAG:
		trace_all_set_ret();
	case TRACE_MODE_TIMELINE:
		/* enable skb clone trace */
		trace_for_each(trace)
			if (TRACE_HAS_ANALYZER(trace, clone))
				trace_set_ret(trace);
		/* enable skb free/drop trace */
		if (!trace_has_end())
			trace_group_enable("life", 1);
		break;
	case TRACE_MODE_DROP:
		if (!trace_ctx.drop_reason)
			pr_warn("skb drop reason is not support by your kernel"
				", drop reason will not be printed\n");
	case TRACE_MODE_BASIC:
	case TRACE_MODE_SOCK:
		if (args->min_latency) {
			pr_err("--min-latency is only supported in default "
			       "and 'diag' mode\n");
			goto err;
		}
		break;
	case TRACE_MODE_MONITOR:
		trace_for_each(trace) {
			if (!trace->monitor) {
				trace_set_invalid_reason(trace, "monitor");
				continue;
			}
			if (!trace_is_func(trace))
				continue;
			switch (trace->monitor) {
			case TRACE_MONITOR_EXIT:
				trace_set_retonly(trace);
			case TRACE_MONITOR_ALL:
				trace_set_ret(trace);
				break;
			default:
				break;
			}
		}
		break;
	default:
		pr_err("mode not supported!\n");
		goto err;
	}

	/* disable traces that don't support sk in SOCK_MODE, and disable
	 * traces that don't support skb in !SOCK_MODE.
	 */
	trace_for_each_cond(trace, (!args->sock && trace->sk &&
				    !trace->skb) ||
				   (args->sock && !trace->sk))
			trace_set_invalid_reason(trace, "sock or sk mode");

	if (args->ret) {
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
	}

	if (args->netns_current) {
		bpf_args->netns = file_inode("/proc/self/ns/net");
		pr_debug("current netns inode is: %u\n", bpf_args->netns);
	}

	bpf_args->trace_mode = 1 << trace_ctx.mode;
	trace_ctx.detail = bpf_args->detail;

	if (args->pkt_len) {
		u32 len_1, len_2;
		char buf[32];

		if (sscanf(args->pkt_len, "%u-%u%s", &len_1, &len_2,
			buf) == 2) {
			bpf_args->pkt.enable_pkt_len_1 = true;
			bpf_args->pkt.pkt_len_1 = len_1;
			bpf_args->pkt.enable_pkt_len_2 = true;
			bpf_args->pkt.pkt_len_2 = len_2;
		} else if (sscanf(args->pkt_len, "%u%s", &len_1,
			buf) == 1) {
			bpf_args->pkt.enable_pkt_len_1 = true;
			bpf_args->pkt.pkt_len_1 = len_1;
			bpf_args->pkt.enable_pkt_len_2 = true;
			bpf_args->pkt.pkt_len_2 = len_1;
		} else {
			pr_err("--pkt_len: invalid format. valid format: "
			       "10 or 10-20\n");
			goto err;
		}
	}

	if (args->tcp_flags) {
		char *cur = args->tcp_flags;
		u8 flags = 0;

		while (*cur != '\0') {
			switch (*cur) {
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
			default:
				pr_err("--tcp-flags: invalid char, valid chars "
				       "are: SAPR\n");
				goto err;
			}
			cur++;
		}
		bpf_args->pkt.enable_tcp_flags = true;
		bpf_args->pkt.tcp_flags = flags;
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

static int trace_prepare_traces()
{
	char func[128], name[136];
	trace_t *trace;

	trace_exec_cond();
	pr_debug("begin to resolve kernel symbol...\n");

	/* make the programs that target kernel function can't be found
	 * load manually.
	 */
	trace_for_each(trace) {
		if (trace_is_invalid(trace) || !trace_is_enable(trace))
			continue;

		if (!trace_is_func(trace) || sym_get_type(trace->name) != SYM_NOT_EXIST)
			continue;

		sprintf(name, "%s.", trace->name);
		if (sym_search_pattern(name, func, true) == SYM_NOT_EXIST) {
			pr_verb("kernel function %s not founded, skipped\n",
				trace->name);
			trace_set_invalid_reason(trace, "not found");
			continue;
		}
		trace->status |= TRACE_ATTACH_MANUAL;
		strcpy(trace->name, func);
		pr_debug("%s is made manual attach\n", trace->name);
	}

	pr_debug("finished to resolve kernel symbol\n");

	return 0;
}

static void trace_prepare_backup()
{
	trace_t *trace, *next;

	trace_for_each(trace) {
		bool hitted = false;

		/* find a enabled leader of a backup chain */
		if (trace->is_backup || !trace->backup ||
		    !trace_is_enable(trace))
			continue;

		next = trace;
		while (next) {
			/* keep the first valid trace and make the others
			 * invalid.
			 */
			if (hitted) {
				trace_set_invalid_reason(next, "backup");
				goto next_bk;
			}
			if (!trace_is_invalid(next)) {
				pr_debug("backup: valid prog for %s is %s\n",
					 next->name, next->prog);
				hitted = true;
			}
next_bk:
			next = next->backup;
		}
	}
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
				fmt = "kprobe/kretprobe";
			else
				fmt = "kprobe";
		} else {
			fmt = "tracepoint";
		}
		pr_verb("\t%s: %s, prog: %s\n", fmt, trace->name,
			trace->prog);
	}
}

int trace_prepare()
{
	int err, i = 0;

#ifndef COMPAT_MODE
	if (!file_exist("/sys/kernel/btf/vmlinux")) {
		pr_err("BTF is not support by your kernel, please compile"
		       "this tool with \"COMPAT=1\"\n");
		err = -ENOTSUP;
		goto err;
	}
#endif

	err = trace_prepare_args();
	if (err)
		goto err;

	for (; i < ARRAY_SIZE(trace_ops_all); i++) {
		if (trace_ops_all[i]->trace_supported()) {
			set_trace_ops(trace_ops_all[i]);
			break;
		}
	}

	if (i == ARRAY_SIZE(trace_ops_all)) {
		pr_err("no ops found!\n");
		err = -EINVAL;
		goto err;
	}

	err = trace_prepare_traces();
	if (err)
		goto err;

	if (geteuid() != 0) {
		pr_err("Please run as root!\n");
		err = -EPERM;
		goto err;
	}

	if (trace_ctx.ops->trace_feat_probe) {
		pr_debug("kernel feature probe begin\n");
		trace_ctx.ops->trace_feat_probe();
		pr_debug("kernel feature probe end\n");
	}

	trace_prepare_backup();
	if (trace_ctx.args.show_traces) {
		trace_show(&root_group);
		exit(0);
	}
	trace_print_enabled();

	return 0;
err:
	return err;
}

int trace_pre_load()
{
	char kret_name[128], regex[128], *func;
	struct bpf_program *prog;
	bool manual, autoload;
	trace_t *trace;

	/* disable all programs that is not enabled or invalid */
	trace_for_each(trace) {
		autoload = !trace_is_invalid(trace) &&
			   trace_is_enable(trace);

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
		if (!trace_is_func(trace) || (trace_is_ret(trace) &&
		    autoload))
			continue;

		sprintf(kret_name, "ret%s", trace->prog);
		prog = bpf_pbn(trace_ctx.obj, kret_name);
		if (!prog) {
			pr_verb("prog: %s not founded\n", kret_name);
			continue;
		}
		bpf_program__set_autoload(prog, false);
		pr_debug("prog: %s is made no-autoload\n", trace->prog);
	}

	return 0;
}

static int trace_bpf_load()
{
	/* skel is already opened */
	if (trace_ctx.obj)
		return 0;

	if (liberate_l())
		pr_warn("failed to set rlimit\n");

	return trace_ctx.ops->trace_load();
}

int trace_bpf_load_and_attach()
{
	trace_t *trace;

	if (trace_bpf_load())
		goto err;

	pr_debug("begin to attach eBPF program...\n");
	if (trace_ctx.ops->trace_attach()) {
		trace_ctx.ops->trace_close();
		goto err;
	}
	pr_debug("eBPF program attached successfully\n");

	if (trace_ctx.ops->trace_ready)
		trace_ctx.ops->trace_ready();

	return 0;
err:
	return -1;
}

static void trace_on_lost(void *ctx, int cpu, __u64 cnt)
{
	pr_err("event losting happened, this can happen when the packets"
	       "we trace are too many.\n"
	       "Please add some filter argument (such as ip or port) to "
	       "prevent this happens.\n");
	exit(-1);
}

int trace_poll()
{
	int map_fd = bpf_object__find_map_fd_by_name(trace_ctx.obj, "m_event");

	if (!map_fd)
		return -1;
	perf_output_cond(map_fd, trace_ctx.ops->trace_poll, trace_on_lost,
			 &trace_ctx.stop);
}
