#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include <packet.h>
#include <skb_utils.h>

#include "shared.h"
#include "kprobe_trace.h"

#define TRACE_PREFIX __trace_

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, TRACE_MAX);
} m_ret SEC(".maps");

enum args_status {
	ARGS_END_OFFSET,
	ARGS_STACK_OFFSET,
	ARGS_RET_OFFSET,
	ARGS_RET_ONLY_OFFSET,
};

#define ARGS_END	(1 << ARGS_END_OFFSET)
#define ARGS_STACK	(1 << ARGS_STACK_OFFSET)
#define ARGS_RET	(1 << ARGS_RET_OFFSET)
#define ARGS_RET_ONLY	(1 << ARGS_RET_ONLY_OFFSET)

typedef struct {
	u16	func;
	u16	status;
} args_t;

PARAM_DEFINE_BOOL(drop_reason, false);

static inline void get_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref)
		return;
	(*ref)++;
}

static inline int put_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref || *ref <= 0)
		return 1;
	(*ref)--;
	return 0;
}

static inline int nettrace_trace(void *regs, struct sk_buff *skb,
				 event_t *e, int size, int func)
{
	packet_t *pkt = &e->pkt;

	if (!skb || probe_parse_skb(skb, pkt))
		return 0;

	pkt->ts = bpf_ktime_get_ns();
	e->key = (u64)(void *)skb;

	bpf_perf_event_output(regs, &m_event, BPF_F_CURRENT_CPU,
			      e, size);
	get_ret(func);
	return 0;
}

static inline int nettrace_ret(struct pt_regs *regs, int func)
{
	retevent_t event = {
		.ts = bpf_ktime_get_ns(),
		.func = func,
		.val = PT_REGS_RC(regs),
	};

	if (put_ret(func))
		return 0;

	EVENT_OUTPUT(regs, event);
	return 0;
}

#define DEFINE_KPROBE_RAW(name, skb_init)			\
	static inline int fake__##name(struct pt_regs *ctx, struct sk_buff *skb,	\
				      int func);		\
	SEC("kretprobe/"#name)					\
	int BPF_KPROBE(ret__trace_##name)			\
	{							\
		return nettrace_ret(ctx, INDEX_##name);		\
	}							\
	SEC("kprobe/"#name)					\
	int BPF_KPROBE(__trace_##name)				\
	{							\
		struct sk_buff *skb = (void *)skb_init;		\
		return fake__##name(ctx, skb, INDEX_##name);	\
	}							\
	static inline int fake__##name(struct pt_regs *ctx, struct sk_buff *skb,	\
				      int func)
#define DEFINE_KPROBE(name, skb_index)				\
	DEFINE_KPROBE_RAW(name, PT_REGS_PARM##skb_index(ctx))

#define KPROBE_DEFAULT(name, skb_index)				\
	DEFINE_KPROBE(name, skb_index)				\
	{							\
		event_t e = { .func = func };			\
		return nettrace_trace(ctx, skb, &e,		\
				      sizeof(event_t), func);	\
	}

#define DEFINE_TP(name, cata, tp, offset)			\
	static inline int fake_##name(void *ctx, struct sk_buff *skb,	\
				      int func);		\
	SEC("tp/"#cata"/"#tp)					\
	int __trace_##name(void *ctx) {				\
		struct sk_buff *skb = *(void **)(ctx + offset);	\
		return fake_##name(ctx, skb, INDEX_##name);	\
	}							\
	static inline int fake_##name(void *ctx, struct sk_buff *skb,	\
				  int func)
#define TP_DEFAULT(name, cata, tp, offset)			\
	DEFINE_TP(name, cata, tp, offset)			\
	{							\
		event_t e = { .func = func };			\
		return nettrace_trace(ctx, skb, &e,		\
				      sizeof(event_t), func);	\
	}
_DEFINE_PROBE(KPROBE_DEFAULT, TP_DEFAULT)

struct kfree_skb_args {
	u64 pad;
	void *skb;
	void *location;
	unsigned short protocol;
	int reason;
};

DEFINE_TP(kfree_skb, skb, kfree_skb, 8)
{
	drop_event_t e = { .event = { .func = func } };
	struct kfree_skb_args *args = ctx;

	e.location = (unsigned long)args->location;
	if (PARAM_CHECK_BOOL(drop_reason))
		e.reason = args->reason;

	return nettrace_trace(ctx, skb, &e.event, sizeof(e), func);
}

DEFINE_KPROBE_RAW(__netif_receive_skb_core_pskb,
	      _(*(void **)(PT_REGS_PARM1(ctx))))
{
	event_t e = { .func = func };
	return nettrace_trace(ctx, skb, &e, sizeof(e), func);
}

DEFINE_KPROBE(ipt_do_table, 1)
{
	struct nf_hook_state *state = (void *)PT_REGS_PARM2(ctx);
	struct xt_table *table = (void *)PT_REGS_PARM3(ctx);
	nf_event_t e = {
		.event = { .func = func, },
		.hook = _(state->hook),
	};

	bpf_probe_read(e.table, sizeof(e.table) - 1, table->name);
	return nettrace_trace(ctx, skb, &e.event, sizeof(e), func);
}

DEFINE_KPROBE(nf_hook_slow, 1)
{
	struct nf_hook_state *state = (void *)PT_REGS_PARM2(ctx);
	nf_event_t e = { 
		.event = { .func = func, },
		.hook = _(state->hook),
		.pf = _(state->pf),
	};

	return nettrace_trace(ctx, skb, &e.event, sizeof(e), func);
}

char _license[] SEC("license") = "GPL";
