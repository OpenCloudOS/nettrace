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
	/* all fctx is added to global hash table */
	struct hlist_node hash;
	/* fctx is added to the corresponding ctx's list */
	struct list_head list;
	u32 key;
	u16 refs;
} fake_analy_ctx_t;

typedef struct {
	/* packet that belongs to the same context */
	struct list_head list;
	fake_analy_ctx_t *fake_ctx;
	analy_ctx_t *ctx;
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
} analy_entry_t;

typedef struct {
	analy_entry_t *entry;
	retevent_t *event;
} analy_exit_t;

typedef struct {
	struct list_head list;
	u16 cpu;
	u8 data[0];
} data_list_t;

typedef enum analyzer_result {
	RESULT_CONT = 0,
	RESULT_CONSUME,
} analyzer_result_t;

typedef struct analyzer {
	analyzer_result_t (*analy_entry)(trace_t *trace, analy_entry_t *e);
	analyzer_result_t (*analy_exit)(trace_t *trace, analy_exit_t *e);
	char *name;
	u32 mode;
} analyzer_t;

#define ANALY_ENTRY_TO_RETURN	(1 << 0)
#define ANALY_ENTRY_EXTINFO	(1 << 1)
#define ANALY_ENTRY_MSG		(1 << 2)
#define ANALY_ENTRY_MSG_CONST	(1 << 3)

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
	rule_run_ret(e->entry, trace, e->event->val);			\
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
DECLARE_ANALYZER(reset);
DECLARE_ANALYZER(default);

#define pr_debug_ctx(fmt, key, ctx, args...)	\
	pr_debug("key=%x, ctx=%llx, ctx-ref=%d, " fmt, key, PTR2X(ctx), ((ctx) ? (ctx)->refs : 0), ##args)

void ctx_poll_handler(void *raw_ctx, void *data, u32 size);
void basic_poll_handler(void *ctx, void *data, u32 size);
void async_poll_handler(void *ctx, void *data, u32 size);
void latency_poll_handler(void *ctx, void *data, u32 size);

analy_entry_t *
tracing_analy_exit(trace_t *trace, retevent_t *event, fake_analy_ctx_t *fctx);
int tracing_analy_entry(trace_t *trace, analy_entry_t *e);

int stats_poll_handler();
int func_stats_poll_handler();

static inline trace_t *get_trace_from_analy_entry(analy_entry_t *e)
{
	return get_trace(e->event->func);
}

static inline void get_analy_ctx(analy_ctx_t *ctx)
{
	ctx->refs++;
}

static inline void put_analy_ctx(analy_ctx_t *ctx)
{
	ctx->refs--;
}

static inline u32 get_entry_dela_us(analy_entry_t *n, analy_entry_t *o)
{
	if (n == o)
		return 0;

	return (n->event->pkt.ts - o->event->pkt.ts) / 1000;
}

static inline u32 get_lifetime_us(analy_ctx_t *ctx, bool skip_last)
{
	analy_entry_t *first, *last;
	trace_t *t;

	first = list_first_entry(&ctx->entries, analy_entry_t, list);
	last = list_last_entry(&ctx->entries, analy_entry_t, list);

	t = get_trace_from_analy_entry(last);
	if (skip_last && !(t->status & TRACE_CFREE)) {
		if (first == last)
			return 0;
		last = list_prev_entry(last, list);
	}

	return get_entry_dela_us(last, first);
}

static inline u32 get_lifetime_ms(analy_ctx_t *ctx, bool skip_last)
{
	return get_lifetime_us(ctx, skip_last) / 1000;
}

static inline void get_fake_analy_ctx(fake_analy_ctx_t *fctx)
{
	/* the case of new created fake_ctx */
	if (!fctx->refs)
		get_analy_ctx(fctx->ctx);
	fctx->refs++;
}

static inline void put_fake_analy_ctx(fake_analy_ctx_t *fctx)
{
	fctx->refs--;
	if (fctx->refs <= 0) {
		put_analy_ctx(fctx->ctx);
		/* remove from the global hash table, it is still in the ctx
		 * hash table
		 */
		hlist_del(&fctx->hash);
		pr_debug_ctx("fctx=%llx, fake ctx done\n", fctx->key, fctx->ctx,
			     PTR2X(fctx));
	}
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

static inline void entry_set_msg_const(analy_entry_t *e, char *info)
{
	e->msg = info;
	e->status |= ANALY_ENTRY_MSG_CONST;
}

static inline analy_entry_t *analy_entry_alloc(void *data, u32 size)
{
	analy_entry_t *entry = calloc(1, sizeof(*entry));
	int copy_size = size;
	void *event;

	if (!entry)
		return NULL;

	if (size > MAX_EVENT_SIZE + 8) {
		pr_err("trace data is too big! size: %u, max: %lu\n",
		       size, MAX_EVENT_SIZE);
		return NULL;
	}
	copy_size = MIN(size, MAX_EVENT_SIZE);
	event = malloc(copy_size);

	memcpy(event, data, copy_size);
	entry->event = event;
	return entry;
}

static inline bool mode_has_context()
{
	return trace_ctx.mode_mask & TRACE_MODE_CTX_MASK;
}

static inline int func_get_type(void *data)
{
	return ((event_t *)data)->meta;
}

#endif
