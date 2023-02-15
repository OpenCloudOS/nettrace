// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_TRACE
#define _H_TRACE

#include <stdbool.h>
#include <list.h>
#include <sys_utils.h>
#include <net_utils.h>

#include "progs/shared.h"
#include <bpf_utils.h>
#include "progs/kprobe_trace.h"

enum trace_type {
	TRACE_FUNCTION,
	TRACE_TP,
};

struct analyzer;

#define TRACE_LOADED		(1 << 0)
#define TRACE_ENABLE		(1 << 1)
#define TRACE_INVALID		(1 << 2)
#define TRACE_RET		(1 << 3)
#define TRACE_STACK		(1 << 4)
#define TRACE_ATTACH_MANUAL	(1 << 5)
#define TRACE_CHECKED		(1 << 6)

#define trace_for_each(pos) list_for_each_entry(pos, &trace_list, all)

typedef struct trace_group {
	char	*name;
	char	*desc;
	struct list_head children;
	struct list_head list;
	struct list_head traces;
} trace_group_t;

typedef struct trace {
	/* name of the kernel function this trace targeted */
	char	name[128];
	char	*desc;
	char	*msg;
	/* name of the eBPF program */
	char	*prog;
	enum trace_type type;
	char	*cond;
	char	*regex;
	char	*tp;
	int	skb;
	/* traces in a global list */
	struct list_head all;
	/* traces in the same group */
	struct list_head list;
	/* list head of rules that belongs to this trace */
	struct list_head rules;
	/* traces that share the same target */
	struct trace *sibling;
	int	index;
	u32	status;
	trace_group_t *parent;
	struct analyzer *analyzer;
	/* if this trace should be enabled by default */
	bool	def;
	bool	mutex;
} trace_t;

typedef struct trace_args {
	bool timeline;
	bool ret;
	bool intel;
	bool intel_quiet;
	bool intel_keep;
	bool basic;
	bool drop;
	bool date;
	bool drop_stack;
	bool show_traces;
	char *traces;
} trace_args_t;

typedef struct {
	/* open and initialize the bpf program */
	int (*trace_load)();
	/* load and attach the bpf program */
	int (*trace_attach)();
	void (*trace_poll)(void *ctx, int cpu, void *data, u32 size);
	int (*trace_anal)(event_t *e);
	void (*trace_close)();
	void (*trace_ready)();
	void (*print_stack)(int key);
	struct analyzer *analyzer;
} trace_ops_t;

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

#define BPF_ARG_GET(name) (trace_ctx.bpf_args.name)

extern trace_ops_t probe_ops;
extern trace_context_t trace_ctx;

extern trace_t *all_traces[];
extern trace_group_t root_group;
extern int trace_count;
extern struct list_head trace_list;

#define FNC(name)		extern trace_t trace_##name;
#define FN(name, index)		FNC(name)
#define FN_tp(name, a1, a2, a3) FNC(name)
DEFINE_ALL_PROBES(FN, FN_tp, FNC)

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

static inline void trace_set_invalid(trace_t *t)
{
	pr_debug("trace name=%s, prog=%s is made invalid\n", t->name,
		 t->prog);
	t->status |= TRACE_INVALID;
}

static inline bool trace_is_invalid(trace_t *t) 
{
	return t->status & TRACE_INVALID;
}

static inline void trace_set_ret(trace_t *t)
{
	t->status |= TRACE_RET;
}

static inline bool trace_is_ret(trace_t *t)
{
	return t->status & TRACE_RET;
}

static inline int trace_set_stack(trace_t *t)
{
	int i = 0;

	for (; i < MAX_FUNC_STACK; i++) {
		if (!trace_ctx.bpf_args.stack_funs[i]) {
			trace_ctx.bpf_args.stack_funs[i] = t->index;
			break;
		}
	}
	if (i == MAX_FUNC_STACK) {
		pr_err("stack trace is full!\n");
		return -1;
	}

	trace_ctx.bpf_args.stack = true;
	t->status |= TRACE_STACK;
	return 0;
}

static inline bool trace_is_stack(trace_t *t)
{
	return t->status & TRACE_STACK;
}

static inline bool trace_is_func(trace_t *t)
{
	return t->type == TRACE_FUNCTION;
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

void trace_show(trace_group_t *group);
void init_trace_group();
trace_group_t *search_trace_group(char *name);
int trace_enable(char *name);
int trace_group_enable(char *name);
int trace_prepare();
int trace_bpf_attach();
int trace_poll();
bool trace_analyzer_enabled(struct analyzer *analyzer);

#endif
