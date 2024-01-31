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
static try_inline void try_trace_stack(context_info_t *info)
{
	int i = 0, key;
	u16 *funcs;

	if (!info->args->stack)
		return;

	funcs = info->args->stack_funs;

#pragma unroll
	for (; i < MAX_FUNC_STACK; i++) {
		if (!funcs[i])
			break;
		if (funcs[i] == info->func)
			goto do_stack;
	}
	return;

do_stack:
	key = bpf_get_stackid(info->ctx, &m_stack, 0);
	info->e->stack_id = key;
}
#else
static try_inline void try_trace_stack(context_info_t *info) { }
#endif

static try_inline int filter_by_netns(context_info_t *info)
{	
	struct sk_buff *skb = info->skb;
	struct net_device *dev;
	u32 inode, netns;
	struct net *ns;

	if (!bpf_core_field_exists(possible_net_t, net))
		return 0;

	netns = info->args->netns;
	if (!netns && !info->args->detail)
		return 0;

	dev = _C(skb, dev);
	if (!dev) {
		struct sock *sk = _C(skb, sk);
		if (!sk)
			goto no_ns;
		ns = _C(sk, __sk_common.skc_net.net);
	} else {
		ns = _C(dev, nd_net.net);
	}

	if (!ns)
		goto no_ns;

	inode = _C(ns, ns.inum);
	if (info->args->detail)
		((detail_event_t *)info->e)->netns = inode;

	return netns ? netns != inode : 0;
no_ns:
	return !!netns;
}

static __always_inline void handle_event_output(context_info_t *info,
						const int size)
{
	if (!size)
		return;

	EVENT_OUTPUT_PTR(info->ctx, info->e, size);
}

/* The event_size here is to be compatible with 4.X kernel, the compiler
 * will optimize it to imm.
 */
static try_inline int handle_entry(context_info_t *info, const int event_size)
{
	bpf_args_t *args = (void *)info->args;
	struct sk_buff *skb = info->skb;
	bool *matched, skip_life;
	event_t *e = info->e;
	packet_t *pkt;
	u32 pid;

	if (!args->ready)
		goto err;

	pr_debug_skb("begin to handle, func=%d", info->func);
	skip_life = (args->trace_mode & MODE_SKIP_LIFE_MASK) ||
		args->pkt_fixed;
	pid = (u32)bpf_get_current_pid_tgid();
	pkt = &e->pkt;
	if (!skip_life) {
		matched = bpf_map_lookup_elem(&m_matched, &skb);
		if (matched && *matched) {
			probe_parse_skb_always(skb, pkt);
			filter_by_netns(info);
			goto skip_filter;
		}
	}

	if (args_check(args, pid, pid) || filter_by_netns(info))
		goto err;

	if (args->trace_mode == TRACE_MODE_SOCK_MASK) {
		if (probe_parse_sk(info->sk, &e->ske))
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
		detail->ifname[0] = '\0';
	}

out:
	pr_debug_skb("pkt matched");
	try_trace_stack(info);
	pkt->ts = bpf_ktime_get_ns();
	e->key = (u64)(void *)skb;
	e->func = info->func;

	handle_event_output(info, event_size);

#ifdef BPF_FEAT_TRACING
	e->retval = info->retval;
#endif

	if (!skip_life)
		get_ret(info->func);
	return 0;
err:
	return -1;
}

static try_inline int handle_destroy(context_info_t *info)
{
	if (!(info->args->trace_mode & MODE_SKIP_LIFE_MASK))
		bpf_map_delete_elem(&m_matched, &info->skb);
	return 0;
}

static try_inline int default_handle_entry(context_info_t *info)
{
#ifdef COMPAT_MODE
	detail_event_t __e;

	/* the kernel of version 4.X can't spill const variable to stack,
	 * so we can't pass the e_size to handle_entry() in this case.
	 */
	info->e = (void *)&__e;
	if (info->args->detail) {
		__e = (detail_event_t) {0};
		handle_entry(info, sizeof(detail_event_t));
	} else {
		*(event_t *)&__e = (event_t) {0};
		handle_entry(info, sizeof(event_t));
	}
#else
	DECLARE_EVENT(event_t, e)
	handle_entry(info, e_size);
#endif

	switch (info->func) {
	case INDEX_consume_skb:
	case INDEX___kfree_skb:
		handle_destroy(info);
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
	struct kfree_skb_args *args = info->ctx;
	int reason = 0;

	if (bpf_core_type_exists(enum skb_drop_reason))
		reason = (int)args->reason;
	else if (ARGS_GET_CONFIG(drop_reason))
		reason = (int)_(args->reason);

	DECLARE_EVENT(drop_event_t, e)

	e->location = (unsigned long)args->location;
	e->reason = reason;
	info->skb = args->skb;

	handle_entry(info, e_size);
	handle_destroy(info);
	return 0;
}

DEFINE_KPROBE_INIT(__netif_receive_skb_core_pskb,
		   __netif_receive_skb_core,
		   .skb = _(*(void **)(ctx_get_arg(ctx, 1))))
{
	return default_handle_entry(info);
}

static try_inline int bpf_ipt_do_table(context_info_t *info, struct xt_table *table,
				       struct nf_hook_state *state)
{
	char *table_name;
	DECLARE_EVENT(nf_event_t, e)

	e->hook = _C(state, hook);
	if (bpf_core_type_exists(struct xt_table))
		table_name = _C(table, name);
	else
		table_name = _(table->name);

	bpf_probe_read(e->table, sizeof(e->table) - 1, table_name);
	return handle_entry(info, e_size);
}

DEFINE_KPROBE_SKB_TARGET(ipt_do_table_legacy, ipt_do_table, 1)
{
	struct nf_hook_state *state = info_get_arg(info, 2);
	struct xt_table *table = info_get_arg(info, 3);

	bpf_ipt_do_table(info, table, state);
	return 0;
}

DEFINE_KPROBE_SKB(ipt_do_table, 2)
{
	struct nf_hook_state *state = info_get_arg(info, 3);
	struct xt_table *table = info_get_arg(info, 1);

	bpf_ipt_do_table(info, table, state);
	return 0;
}

DEFINE_KPROBE_SKB(nf_hook_slow, 1)
{
	struct nf_hook_state *state;
	int num;

	state = info_get_arg(info, 2);
	if (info->args->hooks)
		goto on_hooks;

	DECLARE_EVENT(nf_event_t, e)

	if (handle_entry(info, 0))
		return 0;

	e->hook = _C(state, hook);
	e->pf = _C(state, pf);
	handle_event_output(info, e_size);
	return 0;

on_hooks:;
	struct nf_hook_entries *entries = info_get_arg(info, 3);
	DECLARE_EVENT(nf_hooks_event_t, hooks_event)

	if (handle_entry(info, 0))
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
	handle_event_output(info, hooks_event_size);
	return 0;
}

static __always_inline int
bpf_qdisc_handle(context_info_t *info, struct Qdisc *q)
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

	return handle_entry(info, e_size);
}

DEFINE_KPROBE_SKB(sch_direct_xmit, 1) {
	struct Qdisc *q = info_get_arg(info, 2);
	bpf_qdisc_handle(info, q);

	return 0;
}

DEFINE_KPROBE_SKB(pfifo_enqueue, 1) {
	struct Qdisc *q = info_get_arg(info, 2);
	bpf_qdisc_handle(info, q);

	return 0;
}

DEFINE_KPROBE_SKB(pfifo_fast_enqueue, 1) {
	struct Qdisc *q = info_get_arg(info, 2);
	bpf_qdisc_handle(info, q);

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
	struct nft_pktinfo *pkt = info_get_arg(info, 1);
	void *chain_name, *table_name;
	struct nf_hook_state *state;
	struct nft_chain *chain;
	struct nft_table *table;
	DECLARE_EVENT(nf_event_t, e)

	info->skb = (struct sk_buff *)_(pkt->skb);
	if (handle_entry(info, 0))
		return 0;

	if (bpf_core_type_exists(struct nft_pktinfo)) {
		if (!bpf_core_field_exists(pkt->xt))
			state = _C((struct nft_pktinfo___new *)pkt, state);
		else
			state = _C(pkt, xt.state);
	} else {
		/* don't use CO-RE, as nft may be a module */
		state = _(pkt->xt.state);
	}

	chain = info_get_arg(info, 2);
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

	handle_event_output(info, e_size);
	return 0;
}
#endif


/*******************************************************************
 * 
 * Following is socket related custom BPF program.
 * 
 *******************************************************************/

DEFINE_KPROBE_INIT(inet_listen, inet_listen,
		   .sk = _C((struct socket *)ctx_get_arg(ctx, 1), sk))
{
	return default_handle_entry(info);
}

char _license[] SEC("license") = "GPL";
