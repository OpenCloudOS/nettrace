#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"
#include "core.h"

#ifdef KERN_VER
__u32 kern_ver SEC("version") = KERN_VER;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, TRACE_MAX);
} m_ret SEC(".maps");

#ifdef BPF_FEAT_STACK_TRACE
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} m_stack SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 102400);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u8));
} m_matched SEC(".maps");

#ifdef BPF_FEAT_STACK_TRACE
static try_inline void try_trace_stack(context_t *ctx)
{
	int i = 0, key;
	u16 *funcs;

	if (!ctx->args->stack)
		return;

	funcs = ctx->args->stack_funs;

#pragma unroll
	for (; i < MAX_FUNC_STACK; i++) {
		if (!funcs[i])
			break;
		if (funcs[i] == ctx->func)
			goto do_stack;
	}
	return;

do_stack:
	key = bpf_get_stackid(ctx->regs, &m_stack, 0);
	ctx->e->stack_id = key;
}
#else
static try_inline void try_trace_stack(context_t *ctx) { }
#endif

static try_inline int filter_by_netns(context_t *ctx)
{	
	struct sk_buff *skb = ctx->skb;
	struct net_device *dev;
	u32 inode, netns;
	struct net *ns;

	if (!bpf_core_field_exists(possible_net_t, net))
		return 0;

	netns = ctx->args->netns;
	if (!netns && !ctx->args->detail)
		return 0;

	dev = _(skb->dev);
	if (!dev) {
		struct sock *sk = _(skb->sk);
		if (!sk)
			goto no_ns;
		ns = _(sk->__sk_common.skc_net.net);
	} else {
		ns = _(dev->nd_net.net);
	}

	if (!ns)
		goto no_ns;

	inode = _(ns->ns.inum);
	if (ctx->args->detail)
		((detail_event_t *)ctx->e)->netns = inode;

	return netns ? netns != inode : 0;
no_ns:
	return !!netns;
}

static try_inline int handle_entry(context_t *ctx)
{
	bpf_args_t *args = (void *)ctx->args;
	struct sk_buff *skb = ctx->skb;
	bool *matched, skip_life;
	event_t *e = ctx->e;
	packet_t *pkt;
	u32 pid;

	if (!args->ready)
		goto err;

	pr_debug_skb("begin to handle, func=%d", ctx->func);
	skip_life = (args->trace_mode & MODE_SKIP_LIFE_MASK) ||
		args->pkt_fixed;
	pid = (u32)bpf_get_current_pid_tgid();
	pkt = &e->pkt;
	if (!skip_life) {
		matched = bpf_map_lookup_elem(&m_matched, &skb);
		if (matched && *matched) {
			probe_parse_skb_always(skb, pkt);
			filter_by_netns(ctx);
			goto skip_filter;
		}
	}

	if (ARGS_CHECK(args, pid, pid) || filter_by_netns(ctx))
		goto err;

	if (args->trace_mode == TRACE_MODE_SOCK_MASK) {
		if (probe_parse_sk(ctx->sk, &e->ske))
			goto err;
	} else {
		if (probe_parse_skb(skb, pkt))
			goto err;
	}

	if (!skip_life) {
		bool _matched = true;
		bpf_map_update_elem(&m_matched, &skb, &_matched, 0);
	}

skip_filter:
	if (!args->detail)
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
	try_trace_stack(ctx);
	pkt->ts = bpf_ktime_get_ns();
	e->key = (u64)(void *)skb;
	e->func = ctx->func;

	if (ctx->size)
		EVENT_OUTPUT_PTR(ctx->regs, ctx->e, ctx->size);

#ifdef BPF_FEAT_TRACING
	e->retval = ctx->retval;
#endif

	if (!skip_life)
		get_ret(ctx->func);
	return 0;
err:
	return -1;
}

static try_inline int handle_destroy(context_t *ctx)
{
	if (!(ctx->args->trace_mode & MODE_SKIP_LIFE_MASK))
		bpf_map_delete_elem(&m_matched, &ctx->skb);
	return 0;
}

static try_inline int default_handle_entry(context_t *ctx)
{
#ifdef COMPAT_MODE
	if (ctx->args->detail) {
		detail_event_t e = { };
		ctx_event(ctx, e);
		handle_entry(ctx);
	} else {
		event_t e = { };
		ctx_event(ctx, e);
		handle_entry(ctx);
	}
#else
	DECLARE_EVENT(event_t, e)
	handle_entry(ctx);
#endif

	switch (ctx->func) {
	case INDEX_consume_skb:
	case INDEX___kfree_skb:
		handle_destroy(ctx);
		break;
	default:
		break;
	}

	return 0;
}


/**********************************************************************
 * 
 * Following is the definntion of all kind of BPF program.
 * 
 * DEFINE_ALL_PROBES() will define all the default implement of BPF
 * program, and the customize handle of kernel function or tracepoint
 * is defined following.
 * 
 **********************************************************************/

DEFINE_ALL_PROBES(KPROBE_DEFAULT, TP_DEFAULT, FNC)

#ifndef BPF_FEAT_TRACING
struct kfree_skb_args {
	u64 pad;
	void *skb;
	void *location;
	unsigned short protocol;
	int reason;
};
#else
struct kfree_skb_args {
	void *skb;
	void *location;
	u64 reason;
};
#endif

DEFINE_TP_INIT(kfree_skb, skb, kfree_skb)
{
	struct kfree_skb_args *args = ctx->regs;
	int reason = 0;

	if (bpf_core_type_exists(enum skb_drop_reason))
		reason = (int)args->reason;
	else if (ARGS_GET_CONFIG(drop_reason))
		reason = (int)_(args->reason);

	DECLARE_EVENT(drop_event_t, e)

	e->location = (unsigned long)args->location;
	e->reason = reason;
	ctx->skb = args->skb;

	handle_entry(ctx);
	handle_destroy(ctx);
	return 0;
}

DEFINE_KPROBE_INIT(__netif_receive_skb_core_pskb,
		   __netif_receive_skb_core,
		   .skb = _(*(void **)(nt_regs(regs, 1))))
{
	return default_handle_entry(ctx);
}

static try_inline int bpf_ipt_do_table(context_t *ctx, struct xt_table *table,
				       struct nf_hook_state *state)
{
	char *table_name;
	DECLARE_EVENT(nf_event_t, e, .hook = _C(state, hook))

	if (bpf_core_type_exists(struct xt_table))
		table_name = _C(table, name);
	else
		table_name = _(table->name);

	bpf_probe_read(e->table, sizeof(e->table) - 1, table_name);
	return handle_entry(ctx);
}

DEFINE_KPROBE_SKB_TARGET(ipt_do_table_legacy, ipt_do_table, 1)
{
	struct nf_hook_state *state = nt_regs_ctx(ctx, 2);
	struct xt_table *table = nt_regs_ctx(ctx, 3);

	bpf_ipt_do_table(ctx, table, state);
	return 0;
}

DEFINE_KPROBE_SKB(ipt_do_table, 2)
{
	struct nf_hook_state *state = nt_regs_ctx(ctx, 3);
	struct xt_table *table = nt_regs_ctx(ctx, 1);

	bpf_ipt_do_table(ctx, table, state);
	return 0;
}

DEFINE_KPROBE_SKB(nf_hook_slow, 1)
{
	struct nf_hook_state *state;
	size_t size;
	int num;

	state = nt_regs_ctx(ctx, 2);
	if (ctx->args->hooks)
		goto on_hooks;

	DECLARE_EVENT(nf_event_t, e)

	size = ctx->size;
	ctx->size = 0;
	if (handle_entry(ctx))
		return 0;

	e->hook = _C(state, hook);
	e->pf = _C(state, pf);
	EVENT_OUTPUT_PTR(ctx->regs, ctx->e, size);
	return 0;

on_hooks:;
	struct nf_hook_entries *entries = nt_regs_ctx(ctx, 3);
	__DECLARE_EVENT(hooks, nf_hooks_event_t, hooks_event)

	size = ctx->size;
	ctx->size = 0;
	if (handle_entry(ctx))
		return 0;

	hooks_event->hook = _C(state, hook);
	hooks_event->pf = _C(state, pf);
	num = _(entries->num_hook_entries);

#define COPY_HOOK(i) do {					\
	if (i >= num) goto out;					\
	hooks_event->hooks[i] = (u64)_(entries->hooks[i].hook);	\
} while (0)

	COPY_HOOK(0);
	COPY_HOOK(1);
	COPY_HOOK(2);
	COPY_HOOK(3);
	COPY_HOOK(4);
	COPY_HOOK(5);

	/* following code can't unroll, don't know why......:
	 * 
	 * #pragma clang loop unroll(full)
	 * 	for (i = 0; i < 8; i++)
	 * 		COPY_HOOK(i);
	 */
out:
	EVENT_OUTPUT_PTR(ctx->regs, ctx->e, size);
	return 0;
}

static __always_inline int
bpf_qdisc_handle(context_t *ctx, struct Qdisc *q)
{
	struct netdev_queue *txq;
	unsigned long start;
	DECLARE_EVENT(qdisc_event_t, e)

	txq = _C(q, dev_queue);

	if (bpf_core_helper_exist(jiffies64)) {
		start = _C(txq, trans_start);
		if (start)
			e->last_update = bpf_jiffies64() - start;
	}

	e->qlen = _C(&(q->q), qlen);
	e->state = _C(txq, state);
	e->flags = _C(q, flags);

	return handle_entry(ctx);
}

DEFINE_KPROBE_SKB(sch_direct_xmit, 1) {
	struct Qdisc *q = nt_regs_ctx(ctx, 2);
	bpf_qdisc_handle(ctx, q);

	return 0;
}

DEFINE_KPROBE_SKB(pfifo_enqueue, 1) {
	struct Qdisc *q = nt_regs_ctx(ctx, 2);
	bpf_qdisc_handle(ctx, q);

	return 0;
}

DEFINE_KPROBE_SKB(pfifo_fast_enqueue, 1) {
	struct Qdisc *q = nt_regs_ctx(ctx, 2);
	bpf_qdisc_handle(ctx, q);

	return 0;
}

#ifndef NT_DISABLE_NFT

/* use the 'ignored suffix rule' feature of CO-RE, as described in:
 * https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 */
struct nft_pktinfo___new {
	struct sk_buff			*skb;
	const struct nf_hook_state	*state;
	u8				flags;
	u8				tprot;
	u16				fragoff;
	u16				thoff;
	u16				inneroff;
};

/**
 * This function is used to the kernel version that don't support
 * kernel module BTF.
 */
DEFINE_KPROBE_INIT(nft_do_chain, nft_do_chain, .arg_count = 2)
{
	struct nft_pktinfo *pkt = nt_regs_ctx(ctx, 1);
	void *chain_name, *table_name;
	struct nf_hook_state *state;
	struct nft_chain *chain;
	struct nft_table *table;
	size_t size;
	DECLARE_EVENT(nf_event_t, e)

	ctx->skb = (struct sk_buff *)_(pkt->skb);
	size = ctx->size;
	ctx->size = 0;
	if (handle_entry(ctx))
		return 0;

	if (bpf_core_type_exists(struct nft_pktinfo)) {
		if (!bpf_core_field_exists(pkt->xt))
			state = _C((struct nft_pktinfo___new *)pkt, state);
		else
			state = _C(&(pkt->xt), state);
	} else {
		/* don't use CO-RE, as nft may be a module */
		state = _(pkt->xt.state);
	}

	chain = nt_regs_ctx(ctx, 2);
	if (bpf_core_type_exists(struct nft_chain)) {
		table = _C(chain, table);
		chain_name = _C(chain, name);
		table_name = _C(table, name);
	} else {
		table = _(chain->table);
		chain_name = _(chain->name);
		table_name = _(table->name);
	}
	e->hook	= _C(state, hook);
	e->pf	= _C(state, pf);

	bpf_probe_read_kernel_str(e->chain, sizeof(e->chain), chain_name);
	bpf_probe_read_kernel_str(e->table, sizeof(e->table), table_name);

	EVENT_OUTPUT_PTR(ctx->regs, ctx->e, size);
	return 0;
}
#endif


/*******************************************************************
 * 
 * Following is socket related custom BPF program.
 * 
 *******************************************************************/

DEFINE_KPROBE_INIT(inet_listen, inet_listen,
		   .sk = _C((struct socket *)nt_regs(regs, 1), sk))
{
	return default_handle_entry(ctx);
}

char _license[] SEC("license") = "GPL";
