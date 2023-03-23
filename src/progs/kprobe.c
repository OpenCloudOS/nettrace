#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_utils.h>

#include "kprobe_trace.h"

#define MODE_SKIP_LIFE_MASK (TRACE_MODE_BASIC_MASK | TRACE_MODE_DROP_MASK)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, TRACE_MAX);
} m_ret SEC(".maps");

#ifdef STACK_TRACE
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} m_stack SEC(".maps");
#endif

#ifdef KERN_VER
__u32 kern_ver SEC("version") = KERN_VER;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 102400);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u8));
} m_lookup SEC(".maps");

static try_inline void get_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref)
		return;
	(*ref)++;
}

static try_inline int put_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref || *ref <= 0)
		return 1;
	(*ref)--;
	return 0;
}

#ifdef STACK_TRACE
static try_inline void try_trace_stack(void *regs, bpf_args_t *bpf_args,
				       event_t *e, int func)
{
	int i = 0, key;
	u16 *funcs;

	if (!ARGS_GET(stack))
		return;

	funcs = ARGS_GET(stack_funs);

#pragma unroll
	for (; i < MAX_FUNC_STACK; i++) {
		if (!funcs[i])
			break;
		if (funcs[i] == func)
			goto do_stack;
	}
	return;

do_stack:
	key = bpf_get_stackid(regs, &m_stack, 0);
	e->stack_id = key;
}
#else
static try_inline void try_trace_stack(void *regs, bpf_args_t *bpf_args,
				       event_t *e, int func) { }
#endif

static try_inline int handle_entry(void *regs, struct sk_buff *skb,
				   event_t *e, int size, int func)
{
	packet_t *pkt = &e->pkt;
	bool *matched;
	ARGS_INIT();
	u32 pid;

	if (!ARGS_GET(ready))
		return -1;

	pr_debug_skb("begin to handle, func=%d", func);
	pid = (u32)bpf_get_current_pid_tgid();
	if (ARGS_GET(trace_mode) & MODE_SKIP_LIFE_MASK) {
		if (!probe_parse_skb(skb, pkt))
			goto skip_life;
		return -1;
	}

	matched = bpf_map_lookup_elem(&m_lookup, &skb);
	if (matched && *matched) {
		probe_parse_skb_no_filter(skb, pkt);
	} else if (!ARGS_CHECK(pid, pid) && !probe_parse_skb(skb, pkt)) {
		bool _matched = true;
		bpf_map_update_elem(&m_lookup, &skb, &_matched, 0);
	} else {
		return -1;
	}

skip_life:
	if (!ARGS_GET(detail))
		goto out;

	/* store more (detail) information about net or task. */
	struct net_device *dev = _C(skb, dev);
	detail_event_t *detail = (void *)e;

	bpf_get_current_comm(detail->task, sizeof(detail->task));
	detail->pid = pid;
	if (dev) {
		bpf_probe_read_str(detail->ifname, sizeof(detail->ifname) - 1,
				   dev->name);
		detail->ifindex = _C(dev, ifindex);
	} else {
		detail->ifindex = _C(skb, skb_iif);
	}

out:
	pr_debug_skb("pkt matched");
	try_trace_stack(regs, bpf_args, e, func);
	pkt->ts = bpf_ktime_get_ns();
	e->key = (u64)(void *)skb;

	if (size)
		bpf_perf_event_output(regs, &m_event, BPF_F_CURRENT_CPU,
				      e, size);
	get_ret(func);
	return 0;
}

static try_inline int handle_destroy(struct sk_buff *skb)
{
	if (!(ARGS_GET_CONFIG(trace_mode) & MODE_SKIP_LIFE_MASK))
		bpf_map_delete_elem(&m_lookup, &skb);
	return 0;
}

static try_inline int default_handle_entry(struct pt_regs *ctx,
					   struct sk_buff *skb,
					   int func)
{
	if (ARGS_GET_CONFIG(detail)) {
		detail_event_t e = { .func = func };
		handle_entry(ctx, skb, (void *)&e, sizeof(e), func);
	} else {
		event_t e = { .func = func };
		handle_entry(ctx, skb, &e, sizeof(e), func);
	}

	if (func == INDEX_consume_skb || func == INDEX___kfree_skb)
		handle_destroy(skb);

	return 0;
}

static try_inline int handle_exit(struct pt_regs *regs, int func)
{
	retevent_t event = {
		.ts = bpf_ktime_get_ns(),
		.func = func,
		.val = PT_REGS_RC(regs),
	};

	if (!ARGS_GET_CONFIG(ready) || put_ret(func))
		return 0;

	if (func == INDEX_skb_clone) {
		bool matched = true;
		bpf_map_update_elem(&m_lookup, &event.val, &matched, 0);
	}

	EVENT_OUTPUT(regs, event);
	return 0;
}

#define __BPF_KPROBE(name)	BPF_KPROBE(name)

/* one trace may have more than one implement */
#define __DEFINE_KPROBE_INIT(name, func_name, skb_init)		\
	static try_inline int fake__##name(struct pt_regs *ctx,	\
				       struct sk_buff *skb,	\
				       int func);		\
	SEC("kretprobe/"#func_name)				\
	int __BPF_KPROBE(TRACE_RET_NAME(name))			\
	{							\
		return handle_exit(ctx, INDEX_##name);		\
	}							\
	SEC("kprobe/"#func_name)				\
	int __BPF_KPROBE(TRACE_NAME(name))			\
	{							\
		struct sk_buff *skb = (void *)skb_init;		\
		return fake__##name(ctx, skb, INDEX_##name);	\
	}							\
	static try_inline int fake__##name(struct pt_regs *ctx,	\
					   struct sk_buff *skb,	\
					   int func)

#define DEFINE_KPROBE_INIT(name, skb_init)			\
	__DEFINE_KPROBE_INIT(name, name, skb_init)

#define DEFINE_KPROBE_SKB(name, skb_index)			\
	DEFINE_KPROBE_INIT(name, PT_REGS_PARM##skb_index(ctx))

#define DEFINE_KPROBE_TARGET(name, func_name, skb_index)	\
	__DEFINE_KPROBE_INIT(name, func_name,			\
			     PT_REGS_PARM##skb_index(ctx))

#define KPROBE_DEFAULT(name, skb_index)				\
	DEFINE_KPROBE_SKB(name, skb_index)			\
	{							\
		return default_handle_entry(ctx, skb, func);	\
	}

#define DEFINE_TP(name, cata, tp, offset)			\
	static try_inline int fake_##name(void *ctx, struct sk_buff *skb,	\
				      int func);		\
	SEC("tp/"#cata"/"#tp)					\
	int TRACE_NAME(name)(void *ctx) {			\
		struct sk_buff *skb = *(void **)(ctx + offset);	\
		return fake_##name(ctx, skb, INDEX_##name);	\
	}							\
	static try_inline int fake_##name(void *ctx, struct sk_buff *skb,	\
				  int func)
#define TP_DEFAULT(name, cata, tp, offset)			\
	DEFINE_TP(name, cata, tp, offset)			\
	{							\
		return default_handle_entry(ctx, skb, func);	\
	}
#define FNC(name)

DEFINE_ALL_PROBES(KPROBE_DEFAULT, TP_DEFAULT, FNC)

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
	if (ARGS_GET_CONFIG(drop_reason))
		e.reason = _(args->reason);

	handle_entry(ctx, skb, &e.event, sizeof(e), func);
	handle_destroy(skb);
	return 0;
}

__DEFINE_KPROBE_INIT(__netif_receive_skb_core_pskb, __netif_receive_skb_core,
		    _(*(void **)(PT_REGS_PARM1(ctx))))
{
	return default_handle_entry(ctx, skb, func);
}

#define bpf_ipt_do_table()						\
{									\
	nf_event_t e = {						\
		.event = { .func = func, },				\
		.hook = _C(state, hook),				\
	};								\
									\
	bpf_probe_read(e.table, sizeof(e.table) - 1, _C(table, name));	\
	return handle_entry(ctx, skb, &e.event, sizeof(e), func);	\
}

DEFINE_KPROBE_SKB(ipt_do_table, 1)
{
	struct nf_hook_state *state = (void *)PT_REGS_PARM2(ctx);
	struct xt_table *table = (void *)PT_REGS_PARM3(ctx);

	bpf_ipt_do_table();
}

DEFINE_KPROBE_TARGET(ipt_do_table_new, ipt_do_table, 2)
{
	struct nf_hook_state *state = (void *)PT_REGS_PARM3(ctx);
	struct xt_table *table = (void *)PT_REGS_PARM1(ctx);

	bpf_ipt_do_table();
}

DEFINE_KPROBE_SKB(nf_hook_slow, 1)
{
	nf_event_t e = ext_event_init();
	struct nf_hook_entries *entries;
	struct nf_hook_state *state;
	int num;

	state = (void *)PT_REGS_PARM2(ctx);
	if (ARGS_GET_CONFIG(hooks))
		goto on_hooks;

	if (handle_entry(ctx, skb, &e.event, 0, func))
		return 0;

	e.hook = _C(state, hook);
	e.pf = _C(state, pf);
	EVENT_OUTPUT(ctx, e);
	return 0;

on_hooks:;
	entries = (void *)PT_REGS_PARM3(ctx);
	nf_hooks_event_t hooks_event = ext_event_init();

	if (handle_entry(ctx, skb, &hooks_event.event, 0, func))
		return 0;

	hooks_event.hook = _C(state, hook);
	hooks_event.pf = _C(state, pf);
	num = _(entries->num_hook_entries);

#define COPY_HOOK(i) do {					\
	if (i >= num) goto out;					\
	hooks_event.hooks[i] = (u64)_(entries->hooks[i].hook);	\
} while (0)

	COPY_HOOK(0);
	COPY_HOOK(1);
	COPY_HOOK(2);
	COPY_HOOK(3);
	COPY_HOOK(4);
	COPY_HOOK(5);
	COPY_HOOK(6);
	COPY_HOOK(7);

	/* following code can't unroll, don't know why......:
	 * 
	 * #pragma clang loop unroll(full)
	 * 	for (i = 0; i < 8; i++)
	 * 		COPY_HOOK(i);
	 */
out:
	EVENT_OUTPUT(ctx, hooks_event);
	return 0;
}

#ifndef NT_DISABLE_NFT
#undef NFT_COMPAT
#include "nft_do_chain.c"

#define NFT_COMPAT
#include "nft_do_chain.c"
#endif

DEFINE_KPROBE_SKB(dev_qdisc_enqueue, 1)
{
	struct netdev_queue *txq = (void *)PT_REGS_PARM4(ctx);
	struct Qdisc *q = (void *)PT_REGS_PARM2(ctx);
	qdisc_event_t e = ext_event_init();

	e.qlen = _C(&(q->q), qlen);
	e.state = _C(txq, state);

	return handle_entry(ctx, skb, &e.event, sizeof(e), func);
}

DEFINE_KPROBE_SKB(sch_direct_xmit, 1)
{
	struct netdev_queue *txq = (void *)PT_REGS_PARM4(ctx);
	struct Qdisc *q = (void *)PT_REGS_PARM2(ctx);
	qdisc_event_t e = ext_event_init();

	e.qlen = _C(&(q->q), qlen);
	e.state = _C(txq, state);
	e.flags = _C(q, flags);

	return handle_entry(ctx, skb, &e.event, sizeof(e), func);
}

char _license[] SEC("license") = "GPL";
