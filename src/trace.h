// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_TRACE
#define _H_TRACE

#include <stdbool.h>
#include <list.h>
#include <sys_utils.h>
#include <net_utils.h>

#include "progs/shared.h"
#include "progs/kprobe_trace.h"
#include "progs/kprobe.skel.h"

enum trace_type {
	TRACE_FUNCTION,
	TRACE_TP,
};

struct analyzer;

#define TRACE_LOADED	(1 << 0)
#define TRACE_ENABLE	(1 << 1)
#define TRACE_INVALID	(1 << 2)
#define TRACE_RET	(1 << 3)

#define trace_for_each(pos) list_for_each_entry(pos, &trace_list, sibling)

typedef struct trace_group {
	char	*name;
	char	*desc;
	struct list_head children;
	struct list_head list;
	struct list_head traces;
} trace_group_t;

typedef struct trace {
	char	*name;
	char	*desc;
	char	*msg;
	char	*prog;
	enum trace_type type;
	char	*if_str;
	char	*regex;
	char	*tp;
	int	skb;
	int	pskb;
	struct list_head sibling;
	struct list_head list;
	struct list_head rules;
	int	index;
	u32	status;
	trace_group_t *parent;
	struct analyzer *analyzer;
	bool	def;
} trace_t;

typedef typeof(*((struct kprobe *)0)->rodata) bpf_args_t;

typedef struct trace_args {
	bool timeline;
	bool ret;
	bool intel;
	bool intel_quiet;
	bool intel_keep;
	bool basic;
	char *traces;
} trace_args_t;

typedef struct {
	/* open and initialize the bpf program */
	int (*trace_open)();
	/* load and attach the bpf program */
	int (*trace_load)(trace_t *trace);
	void (*trace_poll)(void *ctx, int cpu, void *data, u32 size);
	int (*trace_anal)(event_t *e);
	void (*trace_close)();
	struct analyzer *analyzer;
} trace_ops_t;

#define TRACE_MODE_BASIC_MASK		(1 << TRACE_MODE_BASIC)
#define TRACE_MODE_TIMELINE_MASK	(1 << TRACE_MODE_TIMELINE)
#define TRACE_MODE_INETL_MASK		(1 << TRACE_MODE_INETL)

typedef struct {
	trace_ops_t	*ops;
	trace_args_t	args;
	bpf_args_t	bpf_args;
	trace_mode_t	mode;
	bool		stop;
	/* if drop reason feature is supported */
	bool		drop_reason;
	/* enable detail output */
	bool		detail;
	struct bpf_object *obj;
} trace_context_t;

#define TRACE_HAS_ANALYZER(trace, name) IS_ANALYZER(trace->analyzer, name)
#define TRACE_ANALYZER_ENABLED(name) trace_analyzer_enabled(&(ANALYZER(name)))

#define BPF_ARG(name) (trace_ctx.bpf_args.arg_##name)

extern trace_ops_t probe_ops;
extern trace_context_t trace_ctx;

extern trace_t *all_traces[];
extern trace_group_t root_group;
extern int trace_count;
extern struct list_head trace_list;

static inline trace_t *get_trace(int index)
{
	if (index < 0 || index > TRACE_MAX)
		return NULL;
	return all_traces[index];
}

static inline void set_trace_ops(trace_ops_t *ops)
{
	trace_ctx.ops = ops;
}

static inline void trace_set_enable(trace_t *t)
{
	t->status |= TRACE_ENABLE;
}

static inline bool trace_is_enable(trace_t *t)
{
	return t->status & TRACE_ENABLE;
}

static inline void trace_set_ret(trace_t *t)
{
	t->status |= TRACE_RET;
}

static inline bool trace_is_ret(trace_t *t)
{
	return t->status & TRACE_RET;
}

static inline void trace_stop()
{
	trace_ctx.stop = true;
}

static inline bool trace_mode_timeline()
{
	return trace_ctx.mode == TRACE_MODE_TIMELINE;
}

static inline bool trace_mode_intel()
{
	return trace_ctx.mode == TRACE_MODE_INETL;
}

/* check if drop reason on kfree_skb is supported */
static inline bool trace_drop_reason_support()
{
	return simple_exec("cat /sys/kernel/debug/tracing/events/skb/"
			   "kfree_skb/format | grep reason") == 0;
}

void trace_show(trace_group_t *group);
void init_trace_group();
trace_group_t *search_trace_group(char *name);
int trace_enable(char *name);
int trace_group_enable(char *name);
int trace_prepare();
int trace_bpf_load();
int trace_poll();
bool trace_analyzer_enabled(struct analyzer *analyzer);

#endif
