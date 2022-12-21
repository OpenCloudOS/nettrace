// SPDX-License-Identifier: MulanPSL-2.0

#include <stdio.h>
#include <list.h>

#include "nettrace.h"
#include "trace.h"
#include "analysis.h"
#include "dropreason.h"

trace_context_t trace_ctx = {
	.mode = TRACE_MODE_TIMELINE,
};

static void _print_trace_group(trace_group_t *group, int level)
{
	char prefix[32] = {}, buf[32];
	trace_group_t *pos;
	trace_t *trace;
	int i = 0;

	for (; i< level; i++)
		prefix[i] = '\t';

	pr_info("%s"PFMT_EMPH"%s"PFMT_END": %s\n", prefix, group->name,
		group->desc);
	if (!list_empty(&group->traces))
		goto print_trace;

	if (list_empty(&group->children))
		return;

	list_for_each_entry(pos, &group->children, list)
		_print_trace_group(pos, level + 1);

	return;
print_trace:
	list_for_each_entry(trace, &group->traces, list) {
		u32 status = trace->status;

		buf[0] = '\0';
		if (status & TRACE_LOADED)
			sprintf_end(buf, ",loaded");
		if (trace_is_enable(trace))
			sprintf_end(buf, ",enable");
		if (status & TRACE_INVALID)
			sprintf_end(buf, ",invalid");
		buf[0] = buf[0] ? ' ' : '\0';

		if (status)
			pr_info("%s  - %s:%s\n",  prefix, trace->name, buf);
		else
			pr_info("%s  - %s\n",  prefix, trace->name);
	}
}

void trace_show(trace_group_t *group)
{
	_print_trace_group(group, 0);
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

int trace_enable(char *name)
{
	trace_t *t;
	bool found;

	trace_for_each(t) {
		if (strcmp(t->name, name))
			continue;
		trace_set_enable(t);
		found = true;
	}
	return !found;
}

static void _trace_group_enable(trace_group_t *group)
{
	trace_group_t *pos;
	trace_t *t;

	list_for_each_entry(pos, &group->children, list)
		_trace_group_enable(pos);

	list_for_each_entry(t, &group->traces, list)
		trace_set_enable(t);
}

/* enable all traces in the group of 'name' */
int trace_group_enable(char *name)
{
	trace_group_t *g = search_trace_group(name);

	if (!g)
		return -1;
	_trace_group_enable(g);
	return 0;
}

static int trace_prepare_trace(trace_t *trace)
{
	char *if_str = trace->if_str;
	char cmd[256], cond[4] = {};
	int kv, ret;

	if (!if_str)
		return 0;

	if (sscanf(if_str, "kernelVersion %2[><=] %d", cond,
		   &kv) != 2) {
		pr_err("if condition error: %s\n", if_str);
		return -1;
	}

	sprintf(cmd, "uname -r | awk -F '.' '$1*100+$2%s%d{exit 1}'",
		cond, kv);
	ret = simple_exec(cmd);
	if (ret != 1)
		trace->status &= ~TRACE_ENABLE;
	return 0;
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
	if (trace->type == TRACE_FUNCTION)
		trace_set_ret(trace);
}

static int trace_prepare_args()
{
	trace_t *drop_trace = search_trace_enabled("kfree_skb");
	trace_args_t *args = &trace_ctx.args;
	char *traces = args->traces;
	trace_t *trace;
	char *tmp, *cur;

	if (args->basic + args->intel + args->drop > 1) {
		pr_err("multi-mode specified!\n");
		goto err;
	}

	if (args->basic)
		trace_ctx.mode = TRACE_MODE_BASIC;

	if (args->intel)
		trace_ctx.mode = TRACE_MODE_INETL;

	if (args->drop_stack) {
		if (trace_set_stack(drop_trace))
			goto err;
	}

	if (args->drop) {
		trace_ctx.mode = TRACE_MODE_DROP;
		trace_set_enable(drop_trace);
		goto skip_trace;
	}

	if (!traces) {
		trace_for_each(trace)
			if (trace->def)
				trace_set_enable(trace);
		goto skip_trace;
	}

	if (strcmp(traces, "?") == 0) {
		trace_show(&root_group);
		exit(0);
	}

	tmp = calloc(strlen(traces) + 1, 1);
	strcpy(tmp, traces);
	cur = strtok(tmp, ",");
	while (cur) {
		if (trace_group_enable(cur) && trace_enable(cur)) {
			pr_err("no valid trace for %s\n", cur);
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
		trace_ctx.bpf_args.drop_reason = true;
		trace_ctx.drop_reason = true;
	}

	switch (trace_ctx.mode) {
	case TRACE_MODE_INETL:
		trace_all_set_ret();
	case TRACE_MODE_TIMELINE:
		/* enable skb clone trace */
		trace_for_each(trace)
			if (TRACE_HAS_ANALYZER(trace, clone))
				trace_set_ret(trace);
		/* enable skb free/drop trace */
		if (!trace_has_end())
			trace_group_enable("life");
		break;
	case TRACE_MODE_BASIC:
		break;
	case TRACE_MODE_DROP: {
		if (!trace_ctx.drop_reason)
			pr_warn("skb drop reason is not support by your kernel"
				", drop reason will not be printed\n");
		break;
	}
	default:
		goto err;
	}
	get_drop_reason(1);

	if (args->ret) {
		switch (trace_ctx.mode) {
		case TRACE_MODE_BASIC:
			pr_err("return value trace is only supported on "
			       "'timeline' and 'intel' mode\n");
			goto err;
		case TRACE_MODE_TIMELINE:
			trace_all_set_ret();
			break;
		case TRACE_MODE_INETL:
		default:
			break;
		}
	}

	trace_ctx.bpf_args.trace_mode = 1 << trace_ctx.mode;
	trace_ctx.detail = trace_ctx.bpf_args.detail;
	/* from v5.14, the struct of nft_pktinfo changed */
	trace_ctx.bpf_args.nft_high = kv_compare(5, 14, 0) >= 0;
	pr_debug("nft high version: %d\n", trace_ctx.bpf_args.nft_high);

	return 0;
err:
	return -1;
}

int trace_prepare()
{
	trace_t *trace;

	if (trace_prepare_args())
		return -1;

	trace_for_each(trace) {
		if (!trace_is_enable(trace))
			continue;
		if (trace_prepare_trace(trace))
			return -1;
	}
	return 0;
}

static int trace_bpf_open()
{
	/* skel is already opened */
	if (trace_ctx.obj)
		return 0;

	if (liberate_l())
		pr_warn("failed to set rlimit\n");

	return trace_ctx.ops->trace_open();
}

int trace_bpf_load()
{
	trace_t *trace;

	if (trace_bpf_open())
		goto err;

	trace_for_each(trace) {
		if (!trace_is_enable(trace))
			continue;
		if (trace_ctx.ops->trace_load(trace)) {
			trace_ctx.ops->trace_close();
			goto err;
		}
	}

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
