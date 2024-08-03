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

#ifdef __F_STACK_TRACE
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} m_stack SEC(".maps");
#endif

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(max_entries, 102400);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(match_val_t));
} m_matched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 512);
} m_stats SEC(".maps");

#ifdef __F_STACK_TRACE
static inline void try_trace_stack(context_info_t *info)
{
	if (!info->args->stack || !(info->func_status & FUNC_STATUS_STACK))
		return;

	info->e->stack_id = bpf_get_stackid(info->ctx, &m_stack, 0);
}
#else
static inline void try_trace_stack(context_info_t *info) { }
#endif

static inline int filter_by_netns(context_info_t *info)
{	
	return 0;
}

static __always_inline void do_event_output(context_info_t *info,
					    const int size)
{
	EVENT_OUTPUT_PTR(info->ctx, info->e, size);
}

static __always_inline int check_rate_limit(bpf_args_t *args)
{
	u64 last_ts = args->__last_update, ts = 0;
	int budget = args->__rate_limit;
	int limit = args->rate_limit;

	if (!limit)
		return 0;

	if (!last_ts) {
		last_ts = bpf_ktime_get_ns();
		args->__last_update = last_ts;
	}

	if (budget <= 0) {
		ts = bpf_ktime_get_ns();
		budget = (((ts - last_ts) / 1000000) * limit) / 1000;
		budget = budget < limit ? budget : limit;
		if (budget <= 0)
			return -1;
		args->__last_update = ts;
	}

	budget--;
	args->__rate_limit = budget;

	return 0;
}

static inline void handle_tiny_output(context_info_t *info)
{
	tiny_event_t e = {
		.func = info->func,
		.meta = FUNC_TYPE_TINY,
#ifdef __PROG_TYPE_TRACING
		.key = (u64)(void *)_(info->skb),
#else
		.key = (u64)(void *)info->skb,
#endif
		.ts = bpf_ktime_get_ns(),
	};

	EVENT_OUTPUT(info->ctx, e);
}

static inline bool mode_has_context(bpf_args_t *args)
{
	return args->trace_mode & TRACE_MODE_BPF_CTX_MASK;
}

static __always_inline u8 get_func_status(bpf_args_t *args, u16 func)
{
	if (func >= TRACE_MAX)
		return 0;

	return args->trace_status[func];
}

static inline bool func_is_free(u8 status)
{
	return status & FUNC_STATUS_FREE;
}

static inline void consume_map_ctx(bpf_args_t *args, void *key)
{
	bpf_map_delete_elem(&m_matched, key);
	args->event_count++;
}

static inline void free_map_ctx(bpf_args_t *args, void *key)
{
	bpf_map_delete_elem(&m_matched, key);
}

static inline void init_ctx_match(void *skb, u16 func)
{
	match_val_t _matched = {
		.ts1 = bpf_ktime_get_ns() / 1000,
		.func1 = func,
	};

	bpf_map_update_elem(&m_matched, &skb, &_matched, 0);
}

static __always_inline void update_stats_key(u32 key)
{
	u64 *stats = bpf_map_lookup_elem(&m_stats, &key);

	if (stats)
		(*stats)++;
}

static __always_inline void update_stats_log(u32 val)
{
	u32 key = 0, i = 0, tmp = 2;

	#pragma clang loop unroll_count(16)
	for (; i < 16; i++) {
		if (val < tmp)
			break;
		tmp <<= 1;
		key++;
	}

	update_stats_key(key);
}

static inline int pre_tiny_output(context_info_t *info)
{
	handle_tiny_output(info);
	if (func_is_free(info->func_status))
		consume_map_ctx(info->args, &info->skb);
	else
		get_ret(info);
	return 1;
}

static inline int pre_handle_latency(context_info_t *info,
				     match_val_t *match_val)
{
	bpf_args_t *args = (void *)info->args;
	u32 delta;

	if (match_val) {
		if (func_is_free(info->func_status)) {
			delta = match_val->ts2 - match_val->ts1;
			/* skip a single match function */
			if (!match_val->func2 || delta < args->latency_min) {
				free_map_ctx(info->args, &info->skb);
				return 1;
			}
			if (args->latency_summary) {
				update_stats_log(delta);
				consume_map_ctx(info->args, &info->skb);
				return 1;
			}
			info->match_val = *match_val;
			return 0;
		}

		match_val->ts2 = bpf_ktime_get_ns() / 1000;
		match_val->func2 = info->func;
		return 1;
	} else {
		/* skip single free function for latency total mode */
		if (func_is_free(info->func_status))
			return 1;
		/* if there isn't any filter, skip handle_entry() */
		if (!args->has_filter) {
			init_ctx_match(info->skb, info->func);
			return 1;
		}
	}
	info->no_event = true;
	return 0;
}

static inline bool trace_mode_latency(bpf_args_t *args)
{
	return args->trace_mode & TRACE_MODE_LATENCY_MASK;
}

/* return value:
 *   -1: invalid and return
 *    0: valid and continue
 *    1: valid and return
 */
static inline int pre_handle_entry(context_info_t *info)
{
	bpf_args_t *args = (void *)info->args;
	int ret = 0;

	if (!args->ready || check_rate_limit(args))
		return -1;

	if (args->max_event && args->event_count >= args->max_event)
		return -1;

	info->func_status = get_func_status(info->args, info->func);
	if (mode_has_context(args)) {
		match_val_t *match_val = bpf_map_lookup_elem(&m_matched,
							     &info->skb);

		/* skip handle_entry() for tiny case */
		if (match_val && args->tiny_output)
			ret = pre_tiny_output(info);
		else if (trace_mode_latency(args))
			ret = pre_handle_latency(info, match_val);
		else if (match_val)
			info->match_val = *match_val;
		else if (args->match_mode &&
			 !(info->func_status & FUNC_STATUS_MATCHER))
			ret = -1;
	}

	if (args->func_stats) {
		if (ret > 0) {
			update_stats_key(info->func);
		} else if (!ret && !args->has_filter) {
			update_stats_key(info->func);
			args->event_count++;
			ret = 1;
		} else {
			info->no_event = true;
		}
	}

	return ret;
}

/* err:
 *   -1: not match
 *    0: match
 *    1: match and no output
 */
static inline void handle_entry_finish(context_info_t *info, int err)
{
	if (mode_has_context(info->args)) {
		if (func_is_free(info->func_status)) {
			if (info->matched)
				consume_map_ctx(info->args, &info->skb);
		} else if (err >= 0) {
			init_ctx_match(info->skb, info->func);
		}
	} else {
		if (err >= 0)
			info->args->event_count++;
	}

	if (err >= 0 && info->args->func_stats)
		update_stats_key(info->func);
}

static inline void try_set_latency(bpf_args_t *args, event_t *e,
				   match_val_t *val)
{
	if (!val->func1 || !trace_mode_latency(args))
		return;

	e->latency = val->ts2 - val->ts1;
	e->latency_func1 = val->func1;
	e->latency_func2 = val->func2;
}

static int auto_inline handle_entry(context_info_t *info)
{
	bpf_args_t *args = (void *)info->args;
	struct sk_buff *skb = info->skb;
	struct net_device *dev;
	detail_event_t *detail;
	event_t *e = info->e;
	pkt_args_t *pkt_args;
	bool mode_ctx, filter;
	packet_t *pkt;
	u32 pid;
	int err;

	pr_debug_skb("begin to handle, func=%d", info->func);
	pid = (u32)bpf_get_current_pid_tgid();
	mode_ctx = mode_has_context(args);
	filter = !info->matched;
	pkt_args = &args->pkt;
	pkt = &e->pkt;

	if (filter && args_check(args, pid, pid))
		goto err;

	/* why we call probe_parse_skb/probe_parse_pkt_sk double times?
	 * because in the inline mode, 4.15 kernel will be confused
	 * with pkt_args.
	 */
	if (!filter) {
		if (info->func_status & FUNC_STATUS_SKB_INVAL) {
			if (!skb || !info->sk)
				goto err;
			/* in this case, hash context by skb, but parse sock */
			probe_parse_pkt_sk(info->sk, pkt, NULL);
		} else {
			if (!skb) {
				pr_bpf_debug("no skb available, func=%d", info->func);
				goto err;
			}
			probe_parse_skb(skb, pkt, NULL);
		}
		goto no_filter;
	}

	if (info->func_status & FUNC_STATUS_SKB_INVAL) {
		if (!skb || !info->sk)
			goto err;
		/* in this case, hash context by skb, but parse sock */
		err = probe_parse_pkt_sk(info->sk, pkt, pkt_args);
	} else if (info->func_status & FUNC_STATUS_SK) {
		if (!info->sk) {
			pr_bpf_debug("no sock available, func=%d", info->func);
			goto err;
		}
		err = probe_parse_sk(info->sk, &e->ske, pkt_args);
	} else {
		if (!skb) {
			pr_bpf_debug("no skb available, func=%d", info->func);
			goto err;
		}
		err = probe_parse_skb(skb, pkt, pkt_args);
	}

	if (err)
		goto err;

no_filter:
	if (filter_by_netns(info) && filter)
		goto err;

	/* latency total mode with filter condition case */
	if (info->no_event)
		return 1;

	if (!args->detail)
		goto out;

	/* store more (detail) information about net or task. */
	dev = _C(skb, dev);
	detail = (void *)e;

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
#ifdef __PROG_TYPE_TRACING
	e->key = (u64)(void *)_(skb);
#else
	e->key = (u64)(void *)skb;
#endif
	e->func = info->func;

	try_set_latency(args, e, &info->match_val);

#ifdef __PROG_TYPE_TRACING
	e->retval = info->retval;
#endif

	if (mode_ctx)
		get_ret(info);
	return 0;
err:
	return -1;
}

static inline int default_handle_entry(context_info_t *info)
{
	bool detail = info->args->detail;
	detail_event_t __e;
#ifndef __F_INIT_EVENT
	int size;
#endif
	int err;

	info->e = (void *)&__e;

#ifndef __F_INIT_EVENT
	if (!detail) {
		size = sizeof(event_t);
		__builtin_memset(&__e, 0, size);
	} else {
		size = sizeof(__e);
		__builtin_memset(&__e, 0, size);
	}
#else
	/* the kernel of version 4.X can't spill const variable to stack,
	 * so we need to initialize the whole event.
	 */
	__builtin_memset(&__e, 0, sizeof(__e));
#endif

	err = handle_entry(info);
	if (!err) {
#ifdef __F_INIT_EVENT
		do_event_output(info, detail ? sizeof(__e) : sizeof(event_t));
#else
		do_event_output(info, size);
#endif
	}

	return err;
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


#ifdef __PROG_TYPE_TRACING
#define info_tp_args(info, offset, index) (void *)((u64 *)(info->ctx) + index)
#else
#define info_tp_args(info, offset, index) ((void *)(info->ctx) + offset)
#endif

DEFINE_TP(kfree_skb, skb, kfree_skb, 0, 8)
{
	int reason = 0;

	if (bpf_core_type_exists(enum skb_drop_reason)) {
		if (bpf_core_field_exists(struct trace_event_raw_kfree_skb, rx_sk))
			reason = *(int *)info_tp_args(info, 36, 3);
		else
			reason = *(int *)info_tp_args(info, 28, 2);
	} else if (info->args->drop_reason) {
		/* use probe, or we will fail if drop reason not supported */
		reason = _(*(int *)info_tp_args(info, 28, 0));
	}

	DECLARE_EVENT(drop_event_t, e)

	e->location = *(u64 *)info_tp_args(info, 16, 1);
	e->reason = reason;

	return handle_entry_output(info, e);
}

DEFINE_KPROBE_INIT(__netif_receive_skb_core_pskb,
		   __netif_receive_skb_core, 3,
		   .skb = _(*(void **)(ctx_get_arg(ctx, 0))))
{
	return default_handle_entry(info);
}

static inline int bpf_ipt_do_table(context_info_t *info, struct xt_table *table,
				   u32 hook)
{
	char *table_name;
	DECLARE_EVENT(nf_event_t, e)

	e->hook = hook;
	if (bpf_core_type_exists(struct xt_table))
		table_name = _C(table, name);
	else
		table_name = _(table->name);

	bpf_probe_read(e->table, sizeof(e->table) - 1, table_name);
	return handle_entry_output(info, e);
}

#if __KERN_MAJOR == 3
DEFINE_KPROBE_INIT(ipt_do_table_legacy, ipt_do_table, 0,
		   .skb = ctx_get_arg(ctx, 0))
{
	struct xt_table *table = info_get_arg(info, 3);
	u32 hook = (u64)info_get_arg(info, 1);

	return bpf_ipt_do_table(info, table, hook);
}
#else
DEFINE_KPROBE_INIT(ipt_do_table_legacy, ipt_do_table, 0,
		   .skb = ctx_get_arg(ctx, 0))
{
	struct nf_hook_state *state = info_get_arg(info, 1);
	struct xt_table *table = info_get_arg(info, 2);

	return bpf_ipt_do_table(info, table, _C(state, hook));
}
#endif

DEFINE_KPROBE_SKB(ipt_do_table, 1, 3)
{
	struct nf_hook_state *state = info_get_arg(info, 2);
	struct xt_table *table = info_get_arg(info, 0);

	return bpf_ipt_do_table(info, table, _C(state, hook));
}

DEFINE_KPROBE_SKB(nf_hook_slow, 0, 4)
{
	struct nf_hook_state *state;
	int err;

	state = info_get_arg(info, 1);
	if (!info->args->hooks) {
		DECLARE_EVENT(nf_event_t, e)

		err = handle_entry(info);
		if (err)
			return err;

		e->hook = _C(state, hook);
		e->pf = _C(state, pf);
		handle_event_output(info, e);
		return 0;
	}

#if __KERN_MAJOR != 3
	DECLARE_EVENT(nf_hooks_event_t, hooks_event)
	struct nf_hook_entries *entries;
	int num, i;

	err = handle_entry(info);
	if (err)
		return err;

	hooks_event->hook = _C(state, hook);
	hooks_event->pf = _C(state, pf);
	entries = info_get_arg(info, 2);
	num = _(entries->num_hook_entries);

#pragma clang loop unroll_count(6)
	for (i = 0; i < 6; i++) {
		if (i >= num)
			break;
		hooks_event->hooks[i] = (u64)_(entries->hooks[i].hook);
	}
	handle_event_output(info, hooks_event);
#endif
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

	return handle_entry_output(info, e);
}

DEFINE_TP(qdisc_dequeue, qdisc, qdisc_dequeue, 3, 32)
{
	struct Qdisc *q = *(struct Qdisc **)info_tp_args(info, 8, 0);
	return bpf_qdisc_handle(info, q);
}

DEFINE_TP(qdisc_enqueue, qdisc, qdisc_enqueue, 2, 24)
{
	struct Qdisc *q = *(struct Qdisc **)info_tp_args(info, 8, 0);
	return bpf_qdisc_handle(info, q);
}

#if !defined(NT_DISABLE_NFT)

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
DEFINE_KPROBE_INIT(nft_do_chain, nft_do_chain, 2,
		   .skb = _(((struct nft_pktinfo *)ctx_get_arg(ctx, 0))->skb))
{
	struct nf_hook_state __attribute__((__unused__))*state;
	void *chain_name, *table_name;
	struct nft_chain *chain;
	struct nft_table *table;
	int err;
	DECLARE_EVENT(nf_event_t, e)

	err = handle_entry(info);
	if (err)
		return err;

#if __KERN_MAJOR == 3
	chain = _C((struct nf_hook_ops *)info_get_arg(info, 1), priv);
#else
	chain = info_get_arg(info, 1);
#endif

#ifdef __F_NFT_NAME_ARRAY
	table = _(chain->table);
	chain_name = &chain->name;
	table_name = &table->name;
#else
	if (bpf_core_type_exists(struct nft_chain)) {
		table = _C(chain, table);
		chain_name = _C(chain, name);
		table_name = _C(table, name);
	} else {
		table = _(chain->table);
		chain_name = _(chain->name);
		table_name = _(table->name);
	}
#endif

	bpf_probe_read_kernel_str(e->chain, sizeof(e->chain), chain_name);
	bpf_probe_read_kernel_str(e->table, sizeof(e->table), table_name);

	handle_event_output(info, e);
	return 0;
}
#endif


/*******************************************************************
 * 
 * Following is socket related custom BPF program.
 * 
 *******************************************************************/

DEFINE_KPROBE_INIT(inet_listen, inet_listen, 2,
		   .sk = _C((struct socket *)ctx_get_arg(ctx, 0), sk))
{
	return default_handle_entry(info);
}

DEFINE_KPROBE_INIT(tcp_ack_update_rtt, tcp_ack_update_rtt, 6,
		   .sk = ctx_get_arg(ctx, 0))
{
	u64 first_rtt, last_rtt;

	first_rtt = (u64)info_get_arg(info, 2);
	last_rtt = (u64)info_get_arg(info, 4);

	if ((long)first_rtt < 0)
		return -1;

	first_rtt = first_rtt / 1000;
	last_rtt = last_rtt / 1000;

	if (first_rtt < info->args->first_rtt || last_rtt < info->args->last_rtt)
		return -1;

	if (info->args->trace_mode & TRACE_MODE_RTT_MASK &&
	    !info->args->has_filter) {
		update_stats_log(first_rtt);
		return 0;
	}

	DECLARE_EVENT(rtt_event_t, e)

	if (handle_entry(info))
		return -1;

	if (info->args->trace_mode & TRACE_MODE_RTT_MASK) {
		update_stats_log(first_rtt);
		return 0;
	}

	e->first_rtt = first_rtt;
	e->last_rtt = last_rtt;

	handle_event_output(info, e);
	return 0;
}

char _license[] SEC("license") = "GPL";
