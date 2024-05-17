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
	struct hlist_node hash;
	struct list_head list;
	u32 key;
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

typedef struct {
	struct list_head list;
	u16 size;
	u16 cpu;
	u8 data[0];
} data_list_t;

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

#define ANALY_ENTRY_RETURNED	(1 << 0)
#define ANALY_ENTRY_EXTINFO	(1 << 1)
#define ANALY_ENTRY_MSG		(1 << 2)
#define ANALY_ENTRY_ONCPU	(1 << 3)
#define ANALY_ENTRY_DLIST	(1 << 4)

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

#define define_pure_event(type, name, data)			\
	pure_##type *name =					\
		(!trace_ctx.detail ? (void *)(data) +		\
			offsetof(type, __event_filed) :		\
			(void *)(data) +			\
			offsetof(detail_##type, __event_filed))

void ctx_poll_handler(void *raw_ctx, int cpu, void *data, u32 size);
void basic_poll_handler(void *ctx, int cpu, void *data, u32 size);
void async_poll_handler(void *ctx, int cpu, void *data, u32 size);
void latency_poll_handler(void *ctx, int cpu, void *data, u32 size);

int stats_poll_handler();
int func_stats_poll_handler();

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

static inline u32 get_entry_dela_us(analy_entry_t *n, analy_entry_t *o)
{
	if (n == o)
		return 0;

	return (n->event->pkt.ts - o->event->pkt.ts) / 1000;
}

static inline u32 get_lifetime_us(analy_ctx_t *ctx, bool skip_last)
{
	analy_entry_t *first, *last;

	first = list_first_entry(&ctx->entries, analy_entry_t, list);
	last = list_last_entry(&ctx->entries, analy_entry_t, list);

	if (skip_last) {
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
