#define KBUILD_MODNAME ""
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "skb_parse.h"
#include "shared.h"
#include "tracing.h"
#include "trace_define.h"
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} m_stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(skb_ctx_t));
} m_skb_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/* the size of the ringbuf, 16M by default. */
	__uint(max_entries, 1 << 24);
} m_ringbuf SEC(".maps");

/* allocate event data */
#define event_define(type) ({						\
	type *___tmp = bpf_ringbuf_reserve(&m_ringbuf, sizeof(type), 0);\
	if (unlikely(!___tmp)) {					\
		bpf_printk("ERROR: failed to alloc %s\n", #type);	\
		return -1;						\
	}								\
	___tmp;								\
})
#define event_output(e) { bpf_ringbuf_submit(e, 0); }
#define event_discard(e) { bpf_ringbuf_discard(e, 0); }

static inline void handle_entry_finish(context_info_t *info, int err);

static __always_inline int check_rate_limit()
{
	u64 last_ts = m_data.__last_update, ts = 0;
	int budget = m_data.__rate_limit;
	int limit = m_config.rate_limit;

	if (!limit)
		return 0;

	if (!last_ts) {
		last_ts = bpf_ktime_get_ns();
		m_data.__last_update = last_ts;
	}

	if (budget <= 0) {
		ts = bpf_ktime_get_ns();
		budget = (((ts - last_ts) / 1000000) * limit) / 1000;
		budget = budget < limit ? budget : limit;
		if (budget <= 0)
			return -1;
		m_data.__last_update = ts;
	}

	budget--;
	m_data.__rate_limit = budget;

	return 0;
}

static inline int handle_tiny_output(context_info_t *info)
{
	tiny_event_t *e = event_define(tiny_event_t);
	
	*e = (tiny_event_t) {
		.func = info->func,
		.meta = FUNC_TYPE_TINY,
		.key = (u32)(u64)_P(info->skb),
		.ts = bpf_ktime_get_ns(),
	};
	event_output(e);

	return 0;
}

static inline bool mode_has_context(void)
{
	return m_config.trace_mode & TRACE_MODE_BPF_CTX_MASK;
}

static __always_inline u8 get_func_flags(u16 func)
{
	if (func >= TRACE_MAX)
		return 0;

	return m_config.trace_flags[func];
}

static inline bool func_is_free(u8 status)
{
	return status & (FUNC_FLAG_FREE | FUNC_FLAG_CFREE);
}

static inline bool func_is_ret(u8 status)
{
	return status & FUNC_FLAG_RET;
}

static inline bool func_is_retonly(u8 status)
{
	return status & FUNC_FLAG_RET_ONLY;
}

static inline bool func_is_cfree(u8 status)
{
	return status & FUNC_FLAG_CFREE;
}

static inline bool func_has_rule(u8 status)
{
	return status & FUNC_FLAG_RULE;
}

static inline void get_skb_ctx(skb_ctx_t *sctx)
{
	sctx->ref++;
}

static inline void put_skb_ctx(skb_ctx_t *sctx, u64 *key)
{
	sctx->ref--;
	if (!sctx->ref) {
		bpf_map_delete_elem(&m_skb_ctx, key);
		m_data.event_count++;
	}
}

static inline void init_skb_ctx(u64 *key, u16 func, bool ts, bool entry_pending)
{
	skb_ctx_t matched = {
		.ts1 = ts ? bpf_ktime_get_ns() / 1000 : 0,
		.func1 = func,
		.ref = entry_pending + 1,
	};

	if (unlikely(bpf_map_update_elem(&m_skb_ctx, key, &matched, 0)))
		bpf_printk("ERROR: failed to init skb ctx, key: %lx\n", *key);
}

volatile __u64 m_stats[512];
static __always_inline void update_stats_key(u32 key)
{
	m_stats[key]++;
}

/* stats for latency mode */
static __always_inline void update_stats_log(u32 val)
{
	u32 key = 0, i = 0, tmp = 2;

	for (; i < LAST_STATS_BUCKET; i++) {
		if (val < tmp)
			break;
		tmp <<= 1;
		key++;
	}

	update_stats_key(key);
}

static __always_inline void check_skb_dead(u8 func_flags, skb_ctx_t *sctx, struct sk_buff *skb)
{
	if (!sctx->dead && func_is_free(func_flags)) {
		sctx->dead = true;
		put_skb_ctx(sctx, (void *)&skb);
	}
}

static inline int pre_tiny_output(context_info_t *info)
{
	handle_tiny_output(info);
	check_skb_dead(info->func_status, info->sctx, info->skb);

	return 1;
}

static inline int pre_handle_latency(context_info_t *info, skb_ctx_t *sctx)
{
	u32 delta;

	if (sctx) {
		if (m_config.latency_free || !func_is_free(info->func_status) ||
		    func_is_cfree(info->func_status)) {
			sctx->ts2 = bpf_ktime_get_ns() / 1000;
			sctx->func2 = info->func;
		}

		/* reenter the matcher, or the free of skb is not traced. */
		if (info->func_status & FUNC_FLAG_MATCHER && sctx->func1 == info->func)
			sctx->ts1 = bpf_ktime_get_ns() / 1000;

		if (func_is_free(info->func_status)) {
			delta = sctx->ts2 - sctx->ts1;

			if (!sctx->func2 || /* skip a single match function */
			    delta < m_config.latency_min ||
			    m_config.latency_summary) {
				check_skb_dead(info->func_status, sctx, info->skb);
				if (m_config.latency_summary)
					update_stats_log(delta);

				return 1;
			}

			info->sctx = sctx;
			return 0;
		}
		return 1;
	} else {
		/* if there isn't any filter, skip handle_entry(). Otherwise,
		 * the skb context will be created in handle_entry_finish().
		 */
		if (!m_config.has_filter) {
			init_skb_ctx((void *)&info->skb, info->func, true, false);
			return 1;
		}
	}
	info->no_output = true;
	return 0;
}

static inline bool trace_mode_latency(void)
{
	return m_config.trace_mode & TRACE_MODE_LATENCY_MASK;
}

static inline bool trace_mode_tiny(void)
{
	return m_config.trace_mode & TRACE_MODE_TINY_MASK;
}

/* return value:
 *   0: valid and continue to handle the entry event
 *   otherwise: finish directly
 */
static inline int pre_handle_entry(context_info_t *info, u16 func, bool is_return)
{
	int ret = 0;

	if (!m_data.ready || check_rate_limit())
		return -1;

	if (m_config.max_event && m_data.event_count >= m_config.max_event)
		return -1;

	info->func_status = get_func_flags(func);
	if (mode_has_context()) {
		skb_ctx_t *sctx = info->sctx ?: bpf_map_lookup_elem(&m_skb_ctx, &info->skb);

		info->is_return = is_return;
		if (!sctx) {
			/* skip no-matcher function in match mode if it is not
			 * matched.
			 */
			if (m_config.match_mode && !(info->func_status & FUNC_FLAG_MATCHER))
				return -1;
			/* If the first function is a free, just ignore it. */
			if (func_is_free(info->func_status))
				return -1;
		}

		info->sctx = sctx;
		if (trace_mode_tiny())
			ret = pre_tiny_output(info);
		else if (trace_mode_latency())
			ret = pre_handle_latency(info, sctx);

		/* skip the entry handle and goto the entry finish directly. */
		if (ret > 0)
			handle_entry_finish(info, 0);
	} else {
		/* function call count stats mode, no output is needed in this mode.
		 * Can't be used together with latency mode.
		 *
		 * Skip the entry handle if there is no filter or it is required to
		 * skip the entry already.
		 */
		if (m_config.func_stats && !m_config.has_filter) {
			update_stats_key(func);
			m_data.event_count++;
			return 1;
		}
	}
	info->no_output = info->no_output || m_config.func_stats;

	return ret;
}

/* err:
 *   -1: not match
 *    0: match
 *    1: match and no output
 */
static inline void handle_entry_finish(context_info_t *info, int err)
{
	skb_ctx_t *sctx;

	if (err < 0)
		return;

	/* the event count will be increased in skb ctx free for context mode */
	if (!mode_has_context()) {
		m_data.event_count++;
		goto out;
	}

	sctx = info->sctx;
	if (sctx) {
		/* for fentry+fexit case, check the free of skb context in put_skb_ctx().
		 * In other case, check it if it is a free function.
		 */
		if (func_is_ret(info->func_status)) {
			if (info->is_return)
				put_skb_ctx(sctx, (void *)&info->skb);
			else
				get_skb_ctx(sctx);
		}

		/* free the skb context in two conditions:
		 *   1. free function called
		 *   2. no pending return for the fentry+fexit progs
		 *
		 * check_skb_dead() must be called after the return checking.
		 * If this is the entry of a free function, we need to make
		 * sure the return pending is counted first.
		 */
		check_skb_dead(info->func_status, sctx, info->skb);
	} else {
		init_skb_ctx((void *)&info->skb, info->func, trace_mode_latency(),
			     func_is_ret(info->func_status));
	}

out:
	if (m_config.func_stats)
		update_stats_key(info->func);
}

static inline void try_set_latency(event_t *e, skb_ctx_t *sctx)
{
	if (!trace_mode_latency() || !sctx || !sctx->func1)
		return;

	e->latency = sctx->ts2 - sctx->ts1;
	e->latency_func1 = sctx->func1;
	e->latency_func2 = sctx->func2;
}

/*
 * the main function to handle the parse and filter.
 *
 * return value:
 *   -1: invalid and finish. It will not be handled by the context
 *    0: valid and event will be output
 *    1: valid, but event will be discarded directly without output it. This
 * is used in the latency mode with filter.
 */
static int handle_entry(context_info_t *info, event_t *e)
{
	struct net_device *dev;
	struct sk_buff *skb;
	packet_t *pkt;
	bool filter;
	int err;

	__cast(skb, info->skb);
	pkt = &e->pkt;
	if (info->func_status & FUNC_FLAG_SK) {
		if (!info->sk)
			goto err;
		err = probe_parse_sk(info->sk, &e->ske, true);
		filter = true;
	} else {
		if (!skb)
			goto err;
		filter = !info->sctx;
		err = probe_parse_skb(skb, info->sk, pkt, filter);
	}

	if (filter && err)
		goto err;

	e->pid = (u32)bpf_get_current_pid_tgid();
	if (filter && args_check(m_config, pid, e->pid))
		goto err;

	/* latency total mode with filter condition case */
	if (info->no_output)
		return 1;

	if (!m_config.detail || !skb)
		goto out;

	/* store more (detail) information about net or task. */
	dev = skb->dev;
	bpf_get_current_comm(e->task, sizeof(e->task));
	if (dev) {
		bpf_core_read_str(e->ifname, sizeof(e->ifname) - 1,
				  &dev->name);
		e->ifindex = dev->ifindex;
	} else {
		e->ifindex = skb->skb_iif;
		e->ifname[0] = '\0';
	}
	e->cpu = bpf_get_smp_processor_id();
out:
	pkt->ts = bpf_ktime_get_ns();
	e->key = (u64)(void *)_P(skb);
	e->func = info->func;
	if (info->func_status & FUNC_FLAG_STACK)
		e->stack_id = bpf_get_stackid(info->ctx, &m_stack, 0);
	e->retval = info->retval;
	e->meta = FUNC_TYPE_FUNC;

	try_set_latency(e, info->sctx);

	return 0;
err:
	return -1;
}

static inline int handle_entry_output(context_info_t *info, event_t *e)
{
	int err = handle_entry(info, e);

	if (err) {
		event_discard(e);
		return err;
	}

	event_output(e);
	return 0;
}

static inline int default_handle_entry(context_info_t *info)
{
	event_t *e = event_define(event_t);

	return handle_entry_output(info, e);
}

volatile const rules_ret_t rules_all[TRACE_MAX];
static __always_inline int handle_exit_rules(u64 retval, int func)
{
	int i, expected, ret_err = retval;

	for (i = 0; i < MAX_RULE_COUNT; i++) {
		bool hit;

		expected = rules_all[func].expected[i];
		switch (rules_all[func].op[i]) {
		case RULE_RETURN_ANY:
			hit = true;
			break;
		case RULE_RETURN_EQ:
			hit = expected == ret_err;
			break;
		case RULE_RETURN_LT:
			hit = expected < ret_err;
			break;
		case RULE_RETURN_GT:
			hit = expected > ret_err;
			break;
		case RULE_RETURN_NE:
			hit = expected != ret_err;
			break;
		default:
			return -1;
		}
		if (hit)
			return 0;
	}

	return -1;
}

/* 
 * this function will be called in fexit in the very begining.
 *
 * return value:
 *   0: continue deal it as entry
 *   1: finish directly
 */
static __always_inline int pre_handle_exit(context_info_t *info, int func)
{
	skb_ctx_t *sctx;
	u64 retval = 0;
	retevent_t *e;
	u8 func_flags;

	func_flags = get_func_flags(func);
	if (func_is_retonly(func_flags))
		goto on_retonly;
	/* 
	 * check if the entry has matched according to the skb context in the
	 * fentry/fexit mode.
	 */
	sctx = bpf_map_lookup_elem(&m_skb_ctx, &info->skb);
	/* check if there are pending return. */
	if (!sctx || sctx->ref - !sctx->dead <= 0)
		return -1;
	info->sctx = sctx;
on_retonly:
	bpf_get_func_ret(info->ctx, &retval);
	/* follow the cloned skb in skb context */
	if (mode_has_context() && func == INDEX_skb_clone && retval)
		init_skb_ctx((void *)&retval, func, false, false);

	/* this is a return only case, handle the fexit fully */
	if (func_is_retonly(func_flags)) {
		/* rule doesn't match, just finish */
		if (func_has_rule(func_flags) && handle_exit_rules(retval, func))
			return 1;
		info->retval = retval;
		return 0;
	}

	/* don't handle the event futher, and return a tiny return event */
	e = event_define(retevent_t);
	/* TODO: convert to direct read */
	e->key = (u64)(void *)_P(info->skb);
	e->func = func;
	e->ts = bpf_ktime_get_ns();
	e->meta = FUNC_TYPE_RET;
	e->val = retval;
	event_output(e);

	/* decrease the skb ref and free the skb context when necessary */
	if (func_is_ret(func_flags))
		put_skb_ctx(sctx, (void *)&info->skb);

	return 1;
}


/**********************************************************************
 *
 * Following is the definntion of all kind of BPF program.
 * 
 * DEFINE_ALL_TRACES() will define all the default implement of BPF
 * program, and the customize handle of kernel function or tracepoint
 * is defined following.
 *
 **********************************************************************/

#define arg_skb(ctx) ctx_get_arg(ctx, BPF_MAGIC_SKB)
#define arg_sk(ctx) ctx_get_arg(ctx, BPF_MAGIC_SK)

#define TRACE_DEFAULT(name)						\
	DEFINE_TRACE_INIT(name, name, .skb = arg_skb(ctx),		\
			  .sk = arg_sk(ctx))				\
	{								\
		return default_handle_entry(info);			\
	}
/* init the skb by the index of func args */
#define DEFINE_TRACE_SKB(name)						\
	DEFINE_TRACE_INIT(name, name, .skb = arg_skb(ctx))

#define DEFINE_TP(name) DEFINE_TP_INIT(name, .skb = arg_skb(ctx))
#define TP_DEFAULT(name) DEFINE_TP(name)				\
	{								\
		return default_handle_entry(info);			\
	}

#define FNC(name)
DEFINE_ALL_TRACES(TRACE_DEFAULT, TP_DEFAULT, FNC)

DEFINE_TP(kfree_skb)
{
	drop_event_t *e;
	u64 reason = 0;
	int err;

	if (bpf_core_type_exists(enum skb_drop_reason))
		reason = info->ctx[2];

	e = event_define(drop_event_t);
	err = handle_entry(info, (event_t *)e);

	if (err) {
		event_discard(e);
		return err;
	}

	e->location = (u64)info_get_arg(info, 1);
	e->reason = reason;

	event_output(e);
	return 0;
}

static inline int bpf_ipt_do_table(context_info_t *info, struct xt_table *table,
				   struct nf_hook_state *state)
{
	nf_event_t *e = event_define(nf_event_t);

	e->hook = state->hook;
	e->pf = state->pf;

	e->chain[0] = '\0';
	if (bpf_core_type_exists(struct xt_table)) {
		bpf_probe_read_kernel_str(e->table, sizeof(e->table) - 1,
					  table->name);
	} else {
		e->table[0] = '\0';
	}

	return handle_entry_output(info, (event_t *)e);
}

DEFINE_TRACE_SKB(ipt_do_table)
{
	struct nf_hook_state *state = info_get_arg(info, 2);
	struct xt_table *table = info_get_arg(info, 0);

	return bpf_ipt_do_table(info, table, state);
}

DEFINE_TRACE_INIT(vlan_do_receive, vlan_do_receive)
{
	struct sk_buff **pskb = (void *)_P(info->ctx[0]);

	__cast(info->skb, _P(*pskb));

	return default_handle_entry(info);
}

DEFINE_TRACE_SKB(nf_hook_slow)
{	
	struct nf_hook_entries *entries;
	nf_hooks_event_t *hooks_event;
	struct nf_hook_state *state;
	int num, i, err;
	nf_event_t *e;

	state = info_get_arg(info, 1);
	if (!m_config.hooks) {
		e = event_define(nf_event_t);

		err = handle_entry(info, (event_t *)e);
		if (err) {
			event_discard(e);
			return err;
		}

		e->hook = state->hook;
		e->pf = state->pf;
		event_output(e);
		return 0;
	}

	hooks_event = event_define(nf_hooks_event_t);
	err = handle_entry(info, (event_t *)hooks_event);
	if (err) {
		event_discard(hooks_event);
		return err;
	}

	hooks_event->hook = state->hook;
	hooks_event->pf = state->pf;
	entries = info_get_arg(info, 2);
	num = _P(entries->num_hook_entries);

	for (i = 0; i < 6 && i < num; i++)
		_LP(hooks_event->hooks + i, &entries->hooks[i].hook);
	event_output(hooks_event);

	return 0;
}

static __always_inline int
bpf_qdisc_handle(context_info_t *info, struct Qdisc *q)
{
	qdisc_event_t *e = event_define(qdisc_event_t);
	struct netdev_queue *txq;
	unsigned long start;

	txq = q->dev_queue;

	if (bpf_core_helper_exist(jiffies64)) {
		start = txq->trans_start;
		if (start)
			e->last_update = bpf_jiffies64() - start;
	}

	e->qlen = q->q.qlen;
	e->state = txq->state;
	e->flags = q->flags;

	return handle_entry_output(info, (event_t *)e);
}

DEFINE_TP(qdisc_dequeue)
{
	struct Qdisc *q = info_get_arg(info, 0);
	return bpf_qdisc_handle(info, q);
}

DEFINE_TP(qdisc_enqueue)
{
	struct Qdisc *q = info_get_arg(info, 0);
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

struct nf_conn_synproxy {
	u32	isn;
	u32	its;
	u32	tsoff;
};

/**
 * This function is used to the kernel version that don't support
 * kernel module BTF.
 */
DEFINE_TRACE_INIT(nft_do_chain, nft_do_chain,
		  .skb = ((struct nft_pktinfo *)ctx_get_arg(ctx, 0))->skb)
{
	nf_event_t *e = event_define(nf_event_t);
	int err;

	err = handle_entry(info, (event_t *)e);
	if (err) {
		event_discard(e);
		return err;
	}

	if (bpf_core_type_exists(struct nft_chain)) {
		struct nft_chain *chain = info_get_arg(info, 1);

		bpf_core_read_str(e->table, sizeof(e->table), _P(_P(chain->table)->name));
		bpf_core_read_str(e->chain, sizeof(e->chain), _P(chain->name));
	} else {
		e->table[0] = '\0';
		e->chain[0] = '\0';
	}

	event_output(e);
	return 0;
}
#endif

DEFINE_TRACE_INIT(tcp_v4_send_reset, tcp_v4_send_reset, .sk = arg_sk(ctx), .skb = arg_skb(ctx))
{
	struct sock_common *skc_common;
	reset_event_t *e;

	skc_common = bpf_core_cast(info->sk, struct sock_common);
	e = event_define(reset_event_t);
	e->state = skc_common->skc_state;
	if (bpf_core_type_exists(enum sk_rst_reason))
		e->reason = (u64)info_get_arg(info, 2);
	else
		e->reason = 0;

	return handle_entry_output(info, (event_t *)e);
}

DEFINE_TRACE_INIT(tcp_v6_send_reset, tcp_v6_send_reset, .sk = arg_sk(ctx), .skb = arg_skb(ctx))
{
	struct sock_common *skc_common;
	reset_event_t *e;

	skc_common = bpf_core_cast(info->sk, struct sock_common);
	e = event_define(reset_event_t);
	e->state = skc_common->skc_state;
	if (bpf_core_type_exists(enum sk_rst_reason))
		e->reason = (u64)info_get_arg(info, 2);
	else
		e->reason = 0;

	return handle_entry_output(info, (event_t *)e);
}

DEFINE_TRACE_INIT(tcp_send_active_reset, tcp_send_active_reset, .sk = arg_sk(ctx))
{
	struct sock_common *skc_common;
	reset_event_t *e;

	skc_common = bpf_core_cast(info->sk, struct sock_common);
	e = event_define(reset_event_t);
	e->state = skc_common->skc_state;
	if (bpf_core_type_exists(enum sk_rst_reason))
		e->reason = (u64)info_get_arg(info, 2);
	else
		e->reason = 0;

	return handle_entry_output(info, (event_t *)e);
}

/*******************************************************************
 * 
 * Following is socket related custom BPF program.
 * 
 *******************************************************************/

DEFINE_TRACE_INIT(inet_listen, inet_listen, .sk = ((struct socket *)ctx_get_arg(ctx, 0))->sk)
{
	return default_handle_entry(info);
}

DEFINE_TRACE_INIT(tcp_ack_update_rtt, tcp_ack_update_rtt, .sk = arg_sk(ctx))
{
	u64 first_rtt, last_rtt;
	rtt_event_t *e;

	first_rtt = (u64)info_get_arg(info, 2);
	last_rtt = (u64)info_get_arg(info, 4);

	if ((long)first_rtt < 0)
		return -1;

	if (first_rtt < m_config.first_rtt || last_rtt < m_config.last_rtt)
		return -1;

	if (m_config.trace_mode & TRACE_MODE_RTT_MASK &&
	    !m_config.has_filter) {
		update_stats_log(first_rtt);
		return 0;
	}

	e = event_define(rtt_event_t);

	if (handle_entry(info, (event_t *)e)) {
		event_discard(e);
		return -1;
	}

	if (m_config.trace_mode & TRACE_MODE_RTT_MASK) {
		update_stats_log(first_rtt);
		event_discard(e);
		return 0;
	}

	e->first_rtt = first_rtt;
	e->last_rtt = last_rtt;

	event_output(e);
	return 0;
}

char _license[] SEC("license") = "GPL";
