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
#define TRACE_RET_ONLY		(1 << 6)
#define TRACE_CFREE		(1 << 7)

#define trace_for_each(pos)		\
	list_for_each_entry(pos, &trace_list, all)
#define trace_for_each_cond(pos, cond)	\
	trace_for_each(pos) 		\
		if (cond)

#define bpf_pbn(obj, name)	\
	bpf_object__find_program_by_name(obj, name)

typedef struct trace_group {
	char	*name;
	char	*desc;
	struct list_head children;
	struct list_head list;
	struct list_head traces;
} trace_group_t;

enum {
	TRACE_MONITOR_EXIT = 1,
	TRACE_MONITOR_ENTRY,
};

typedef struct trace {
	/* name of the kernel function this trace targeted */
	char	name[64];
	char	*desc;
	char	*msg;
	/* name of the eBPF program */
	char	*prog;
	enum trace_type type;
	char	*cond;
	char	*regex;
	char	*tp;
	/* index of skb in function args, start from 1, 0 means no skb */
	u8	skb;
	/* offset of skb in ftrace event */
	u8	skboffset;
	/* the same as skb */
	u8	sk;
	/* the same as skb_offset */
	u8	skoffset;
	/* traces in a global list */
	struct list_head all;
	/* traces in the same group */
	struct list_head list;
	/* list head of rules that belongs to this trace */
	struct list_head rules;
	/* traces that share the same target */
	struct trace *backup;
	bool	is_backup;
	bool	probe;
	/* if this trace should be enabled by default */
	bool	def;
	/* if the BPF program is custom of this trace */
	bool	custom;
	int	monitor;
	int	index;
	int	arg_count;
	u32	status;
	trace_group_t *parent;
	struct analyzer *analyzer;
} trace_t;

typedef struct {
	struct list_head list;
	trace_t * trace;
} trace_list_t;

typedef struct trace_args {
	bool timeline;
	bool ret;
	bool intel;
	bool intel_quiet;
	bool intel_keep;
	bool basic;
	bool monitor;
	bool drop;
	bool date;
	bool drop_stack;
	bool show_traces;
	bool sock;
	bool netns_current;
	bool force;
	bool latency_show;
	bool rtt;
	bool rtt_detail;
	bool latency;
	bool traces_noclone;
	u32  min_latency;
	char *traces;
	char *traces_stack;
	char *trace_matcher;
	char *trace_exclude;
	char *trace_free;
	char *pkt_len;
	char *tcp_flags;
	u32  count;
	char *btf_path;
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
	void (*trace_feat_probe)();
	bool (*trace_supported)();
	void (*prepare_traces)();
	int  (*raw_poll)();
	struct analyzer *analyzer;
} trace_ops_t;

typedef struct {
	trace_ops_t	*ops;
	trace_args_t	args;
	bpf_args_t	bpf_args;
	trace_mode_t	mode;
	__u64		mode_mask;
	bool		stop;
	/* if drop reason feature is supported */
	bool		drop_reason;
	/* enable detail output */
	bool		detail;
	bool		skip_last;
	bool		trace_clone;
	struct bpf_object *obj;
	/* if reset reason feature is supported */
	bool 		reset_reason;
} trace_context_t;

#define TRACE_HAS_ANALYZER(trace, name) IS_ANALYZER(trace->analyzer, name)
#define TRACE_ANALYZER_ENABLED(name) trace_analyzer_enabled(&(ANALYZER(name)))

#define BPF_ARG_GET(name) (trace_ctx.bpf_args.name)

extern trace_context_t trace_ctx;

extern trace_t *all_traces[];
extern trace_group_t root_group;
extern int trace_count;
extern struct list_head trace_list;
extern u32 ctx_count;

#define DECLARE_TRACES(name, ...) extern trace_t trace_##name;
DEFINE_ALL_PROBES(DECLARE_TRACES, DECLARE_TRACES, DECLARE_TRACES)

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

static inline void trace_set_invalid_reason(trace_t *t, const char *reason)
{
	if (reason)
		pr_debug("trace name=%s, prog=%s is made invalid for: %s\n",
			 t->name, t->prog, reason);
	else
		pr_debug("trace name=%s, prog=%s is made invalid\n",
			 t->name, t->prog);
	t->status |= TRACE_INVALID;
}

static inline void trace_set_invalid(trace_t *t)
{
	trace_set_invalid_reason(t, NULL);
}

static inline bool trace_is_invalid(trace_t *t) 
{
	return t->status & TRACE_INVALID;
}

static inline bool trace_is_usable(trace_t *t)
{
	return trace_is_enable(t) && !trace_is_invalid(t);
}

static inline void trace_set_status(int func, int status)
{
	trace_ctx.bpf_args.trace_status[func] |= status;
}

static inline void trace_set_ret(trace_t *t)
{
	trace_set_status(t->index, FUNC_STATUS_RET);
	t->status |= TRACE_RET;
}

static inline bool trace_is_ret(trace_t *t)
{
	return t->status & TRACE_RET;
}

static inline void trace_set_retonly(trace_t *t)
{
	t->status |= TRACE_RET_ONLY;
}

static inline bool trace_is_retonly(trace_t *t)
{
	return t->status & TRACE_RET_ONLY;
}

static inline u8 trace_get_status(int func)
{
	return trace_ctx.bpf_args.trace_status[func];
}

static inline bool trace_using_sk(trace_t *t)
{
	return trace_get_status(t->index) & FUNC_STATUS_SK;
}

static inline int trace_set_stack(trace_t *t)
{
	trace_set_status(t->index, FUNC_STATUS_STACK);
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

static inline bool trace_stopped()
{
	return trace_ctx.stop;
}

static inline bool trace_mode_timeline()
{
	return trace_ctx.mode == TRACE_MODE_TIMELINE;
}

static inline bool trace_mode_diag()
{
	return trace_ctx.mode == TRACE_MODE_DIAG;
}

void trace_show(trace_group_t *group);
void init_trace_group();
trace_group_t *search_trace_group(char *name);
int trace_prepare();
int trace_bpf_load_and_attach();
int trace_poll();
bool trace_analyzer_enabled(struct analyzer *analyzer);
int trace_pre_load();
bpf_args_t *get_bpf_args();

#endif
