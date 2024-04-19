// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_ANALYSIS
#define _H_ANALYSIS

#include "progs/shared.h"
#include "trace.h"

enum rule_level {
	RULE_INFO,
	RULE_WARN,
	RULE_ERROR,
};

typedef struct {
	enum rule_level level;
	enum rule_type type;
	char *msg;
	char *adv;
	struct list_head list;

	union {
		int expected;
		struct {
			int min;
			int max;
		} range;
	};
} rule_t;

#define ANALY_CTX_ERROR	(1 << 0)
#define ANALY_CTX_WARN	(1 << 1)

typedef struct {
	struct list_head entries;
	struct list_head fakes;
	u16 refs;
	u16 status;
} analy_ctx_t;

typedef struct fake_analy_ctx {
	analy_ctx_t *ctx;
	u64 key;
	struct hlist_node hash;
	struct list_head list;
	u16 refs;
} fake_analy_ctx_t;

typedef struct {
	/* packet that belongs to the same context */
	struct list_head list;
	analy_ctx_t *ctx;
	fake_analy_ctx_t *fake_ctx;
	event_t *event;
	/* the first rule matched */
	rule_t *rule;
	/* info used in analysis entry log */
	char *msg;
	/* info used in analysis context result */
	char *extinfo;
	u64 priv;
	u32 status;
	u16 cpu;
	/* this list is used for kretprobe based program */
	struct list_head cpu_list;
} analy_entry_t;

typedef struct {
	retevent_t event;
	analy_entry_t *entry;
	u64	key;
	u16	cpu;
} analy_exit_t;

typedef enum analyzer_result {
	RESULT_CONT,
	RESULT_CONSUME,
	RESULT_FINISH,
} analyzer_result_t;

typedef struct analyzer {
	analyzer_result_t (*analy_entry)(trace_t *trace, analy_entry_t *e);
	analyzer_result_t (*analy_exit)(trace_t *trace, analy_exit_t *e);
	char *name;
	u32 mode;
} analyzer_t;

extern u32 skb_count;

#define ANALY_ENTRY_RETURNED	(1 << 0)
#define ANALY_ENTRY_EXTINFO	(1 << 1)
#define ANALY_ENTRY_MSG		(1 << 2)
#define ANALY_ENTRY_ONCPU	(1 << 3)

#define ANALYZER(name) analyzer_##name
#define DEFINE_ANALYZER_PART(name, type, mode_mask)			\
	analyzer_result_t analyzer_##name##_exit(trace_t *trace,	\
		analy_exit_t *e) __attribute__((weak));			\
	analyzer_result_t analyzer_##name##_entry(trace_t *trace,	\
		analy_entry_t *e) __attribute__((weak));		\
	analyzer_t ANALYZER(name) = {					\
		.analy_entry = analyzer_##name##_entry,			\
		.analy_exit = analyzer_##name##_exit,			\
		.mode = mode_mask,					\
	};								\
	analyzer_result_t analyzer_##name##_##type(trace_t *trace,	\
		analy_##type##_t *e)
#define DEFINE_ANALYZER_ENTRY(name, mode)				\
	DEFINE_ANALYZER_PART(name, entry, mode)
#define DEFINE_ANALYZER_EXIT(name, mode)				\
	DEFINE_ANALYZER_PART(name, exit, mode)
#define DEFINE_ANALYZER_EXIT_FUNC(name)					\
	analyzer_result_t analyzer_##name##_exit(trace_t *trace,	\
		analy_exit_t *e)

#define DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(name)				\
DEFINE_ANALYZER_EXIT_FUNC(name)						\
{									\
	rule_run_ret(e->entry, trace, e->event.val);			\
	return RESULT_CONT;						\
}

#define DECLARE_ANALYZER(name) extern analyzer_t ANALYZER(name)
#define IS_ANALYZER(target, name) (target == &(ANALYZER(name)))

DECLARE_ANALYZER(drop);
DECLARE_ANALYZER(free);
DECLARE_ANALYZER(clone);
DECLARE_ANALYZER(ret);
DECLARE_ANALYZER(iptable);
DECLARE_ANALYZER(nf);
DECLARE_ANALYZER(qdisc);
DECLARE_ANALYZER(rtt);
DECLARE_ANALYZER(default);

#ifndef COMPAT_MODE
#define define_pure_event(type, name, data)			\
	pure_##type *name =					\
		(!trace_ctx.detail ? (void *)(data) +		\
			offsetof(type, __event_filed) :		\
			(void *)(data) +			\
			offsetof(detail_##type, __event_filed))
#else
#define define_pure_event(type, name, data)			\
	detail_##type *name = (void *)(data)
#endif

void tl_poll_handler(void *raw_ctx, int cpu, void *data, u32 size);
void basic_poll_handler(void *ctx, int cpu, void *data, u32 size);
void async_poll_handler(void *ctx, int cpu, void *data, u32 size);

int rtt_poll_handler();

static inline trace_t *get_trace_from_analy_entry(analy_entry_t *e)
{
	return get_trace(e->event->func);
}

static inline trace_t *get_trace_from_analy_exit(analy_exit_t *e)
{
	return get_trace(e->event.func);
}

static inline void get_analy_ctx(analy_ctx_t *ctx)
{
	ctx->refs++;
}

static inline void put_analy_ctx(analy_ctx_t *ctx)
{
	ctx->refs--;
}

static inline u32 get_lifetime_ms(analy_ctx_t *ctx)
{
	analy_entry_t *first, *last;

	first = list_first_entry(&ctx->entries, analy_entry_t, list);
	last = list_last_entry(&ctx->entries, analy_entry_t, list);

	return (last->event->pkt.ts - first->event->pkt.ts) / 1000000;
}

static inline void get_fake_analy_ctx(fake_analy_ctx_t *ctx)
{
	/* the case of new created fake_ctx */
	if (!ctx->refs)
		get_analy_ctx(ctx->ctx);
	ctx->refs++;
}

static inline void put_fake_analy_ctx(fake_analy_ctx_t *ctx)
{
	ctx->refs--;
	if (ctx->refs <= 0)
		put_analy_ctx(ctx->ctx);
}

static inline bool event_is_ret(int size)
{
	return size - 8 <= sizeof(retevent_t);
}

static inline void entry_set_extinfo(analy_entry_t *e, char *info)
{
	e->extinfo = info;
	e->status |= ANALY_ENTRY_EXTINFO;
}

static inline void entry_set_msg(analy_entry_t *e, char *info)
{
	e->msg = info;
	e->status |= ANALY_ENTRY_MSG;
}

static inline bool mode_has_context()
{
	return (1 << trace_ctx.mode) & (TRACE_MODE_TIMELINE_MASK |
		TRACE_MODE_DIAG_MASK);
}

static inline int try_inc_skb_count()
{
	if (!trace_ctx.args.count)
		return 0;

	if (trace_ctx.args.count <= skb_count++) {
		trace_stop();
		return -1;
	}

	return 0;
}

#endif
