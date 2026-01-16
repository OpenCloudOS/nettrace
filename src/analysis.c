// SPDX-License-Identifier: MulanPSL-2.0

#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <unistd.h>
#undef __USE_MISC
#include <net/if.h>
#include <pthread.h>
#include <errno.h>

#include <stdlib.h>
#include <parse_sym.h>

#include "output.h"
#include "trace.h"
#include "analysis.h"
#include "dropreason.h"
#include "rstreason.h"
#include "sys_utils.h"

#define CTX_HASH_LENGTH 1024
static struct hlist_head ctx_hash[CTX_HASH_LENGTH] = {};
const char *level_mark[] = {
	[RULE_INFO]  = "NOTICE",
	[RULE_WARN]  = "WARNING",
	[RULE_ERROR] = "ERROR",
};
u32 ctx_count = 0;

static inline struct hlist_head *get_ctx_hash_head(u32 key)
{
	int index = (key >> 8) % CTX_HASH_LENGTH;
	return &ctx_hash[index];
}

static inline fake_analy_ctx_t *analy_fake_ctx_find(u32 key)
{
	struct hlist_head *head = get_ctx_hash_head(key);
	fake_analy_ctx_t *fake_ctx;
	struct hlist_node *pos;

	hlist_for_each_entry(fake_ctx, pos, head, hash) {
		if (fake_ctx->key == key)
			return fake_ctx;
	}
	return NULL;
}

static inline void analy_fake_ctx_add(fake_analy_ctx_t *fake)
{
	struct hlist_head *head = get_ctx_hash_head(fake->key);
	hlist_add_head(&fake->hash, head);
}

static inline fake_analy_ctx_t
*analy_fake_ctx_alloc(u32 key, analy_ctx_t *ctx)
{
	fake_analy_ctx_t *fake = malloc(sizeof(fake_analy_ctx_t));

	if (!fake)
		return NULL;

	fake->ctx = ctx;
	fake->key = key;
	fake->refs = 0;

	list_add_tail(&fake->list, &ctx->fakes);
	analy_fake_ctx_add(fake);

	get_fake_analy_ctx(fake);
	pr_debug("fake ctx alloc: %llx, %x\n", PTR2X(fake), key);
	return fake;
}

static fake_analy_ctx_t *analy_fake_ctx_fetch(u32 key)
{
	fake_analy_ctx_t *fctx;
	analy_ctx_t *ctx;

	fctx = analy_fake_ctx_find(key);
	if (fctx)
		return fctx;

	ctx = malloc(sizeof(analy_ctx_t));
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->entries);
	INIT_LIST_HEAD(&ctx->fakes);
	ctx->status = 0;
	ctx->refs = 0;

	fctx = analy_fake_ctx_alloc(key, ctx);
	if (!fctx)
		goto err;
	ctx_count++;

	return fctx;
err:
	free(ctx);
	return NULL;
}

static inline void analy_entry_free(analy_entry_t *entry)
{
	if (entry->status & ANALY_ENTRY_EXTINFO)
		free(entry->extinfo);

	if (entry->status & ANALY_ENTRY_MSG)
		free(entry->msg);

	if (entry->status & ANALY_ENTRY_TO_RETURN) {
		trace_t *t = get_trace_from_analy_entry(entry);
		pr_err("entry %s is still on hash pid=%d\n", t->name,
		       entry->event->pid);
	}

	free(entry->event);
	free(entry);
}

static void analy_entry_output(analy_entry_t *entry, analy_entry_t *prev)
{
	static char buf[1024], tinfo[512], func_range[512], __func_range[500];
	bool date = trace_ctx.args.date;
	event_t *e = entry->event;
	rule_t *rule;
	trace_t *t;

	t = get_trace_from_analy_entry(entry);
	pr_debug("output entry(%llx)\n", PTR2X(entry));
	if (e->meta == FUNC_TYPE_TINY) {
		ts_print_ts(buf, ((tiny_event_t *)(void *)e)->ts, date);
		sprintf_end(buf, "[%-20s]", t->name);
		goto do_latency;
	}

	if (trace_ctx.mode == TRACE_MODE_LATENCY) {
		trace_t *t1, *t2;

		t1 = get_trace(e->latency_func1);
		t2 = get_trace(e->latency_func2);
		sprintf(__func_range, "%s -> %s", t1->name, t2->name);
		sprintf(func_range, "[%-36s]", __func_range);
	} else {
		func_range[0] = '\0';
	}

	if (trace_ctx.detail) {
		if (e->ifname[0] == '\0')
			if_indextoname(e->ifindex, e->ifname);

		sprintf(tinfo, "[%x][%-20s]%s[cpu:%-3u][%-5s][%s-%u][ns:%u] ",
			e->key, t->name, func_range, e->cpu, e->ifname,
			e->task, e->pid, e->netns);
	} else if (trace_ctx.mode != TRACE_MODE_DROP) {
		sprintf(tinfo, "[%-20s]%s ", t->name, func_range);
	}

	if (trace_using_sk(t))
		ts_print_sock(buf, &e->ske, tinfo, trace_ctx.args.date);
	else
		ts_print_packet(buf, &e->pkt, tinfo, trace_ctx.args.date);

	if (trace_is_ret(t) && !(entry->status & ANALY_ENTRY_TO_RETURN) &&
	    trace_ctx.args.ret)
		sprintf_end_color(buf, " *return: %d*", (int)entry->priv);

do_latency:
	if (prev && trace_ctx.args.latency_show) {
		u32 delta;

		delta = get_entry_dela_us(entry, prev);
		sprintf_end(buf, " latency: %d.%03dms", delta / 1000,
			    delta % 1000);
	}

	if (entry->msg)
		sprintf_end(buf, "%s", entry->msg);

	if (!entry->rule)
		goto out;

	rule = entry->rule;
	switch (rule->level) {
	case RULE_INFO:
		sprintf_end_color(buf, " *%s*", rule->msg);
		break;
	case RULE_WARN:
		sprintf_warn_color(buf, " *%s*", rule->msg);
		break;
	case RULE_ERROR:
		sprintf_error_color(buf, " *%s*", rule->msg);
		break;
	default:
		break;
	}
out:
	pr_info("%s\n", buf);

	if (trace_is_stack(t) && e->meta != FUNC_TYPE_TINY)
		trace_ctx.ops->print_stack(e->stack_id);
}

static void analy_ctx_free(analy_ctx_t *ctx)
{
	fake_analy_ctx_t *fake, *fake_n;
	analy_entry_t *entry, *n;

	list_for_each_entry_safe(fake, fake_n, &ctx->fakes, list) {
		list_del(&fake->list);
		free(fake);
	}

	list_for_each_entry_safe(entry, n, &ctx->entries, list) {
		list_del(&entry->list);
		analy_entry_free(entry);
	}

	ctx_count--;
	free(ctx);
}

static void analy_diag_handle(analy_ctx_t *ctx)
{
	analy_entry_t *entry;
	rule_t *rule = NULL;
	trace_t *trace;
	int i = 0;

	pr_info_color("---------------- ANALYSIS RESULT ---------------------\n");
	list_for_each_entry(entry, &ctx->entries, list) {
		if (!entry->rule || entry->rule->level == RULE_INFO)
			continue;

		trace = get_trace_from_analy_entry(entry);
		rule = entry->rule;
		i++;

		pr_info("[%d] %s happens in %s(%s):\n\t%s\n", i,
			level_mark[rule->level], trace->name,
			trace->parent->name, rule->msg);

		if (entry->extinfo)
			pr_info("%s\n", entry->extinfo);

		if (rule->adv) {
			pr_info_color("    fix advice:\n\t");
			pr_info("%s\n", rule->adv);
		}
		pr_info("\n");
	}

	if ((ctx->status & ANALY_CTX_ERROR) && !trace_ctx.args.intel_keep) {
		pr_info_color("analysis finished!");
		trace_stop();
	} else if (!rule) {
		pr_info("this is a good packet!\n");
	}
}

void analy_ctx_output(analy_ctx_t *ctx)
{
	analy_entry_t *entry, *prev = NULL;
	struct list_head *head;
	static char keys[1024];
	fake_analy_ctx_t *fake;
	u32 latency = 0;

	if (trace_mode_diag() && trace_ctx.args.intel_quiet &&
	    !ctx->status)
		goto free_ctx;

	if (trace_ctx.args.latency_show) {
		latency = get_lifetime_us(ctx, trace_ctx.skip_last);
		if (latency < trace_ctx.args.min_latency)
			goto free_ctx;
	}

	keys[0] = '\0';
	list_for_each_entry(fake, &ctx->fakes, list)
		sprintf_end(keys, ",%08x", fake->key);

	keys[0] = ' ';
	pr_info_color("*****************%s ***************\n", keys);
	head = &ctx->entries;
	list_for_each_entry(entry, head, list) {
		analy_entry_output(entry, prev);
		prev = entry;
	}

	if (trace_ctx.args.latency_show) {
		pr_info("total latency: %d.%03dms\n", latency / 1000,
			latency % 1000);
	}

	if (trace_mode_diag())
		analy_diag_handle(ctx);

	pr_info("\n");
free_ctx:
	analy_ctx_free(ctx);
}

static int try_run_entry(trace_t *trace, analyzer_t *analyzer,
			 analy_entry_t *entry)
{
	u32 mode = 1 << trace_ctx.mode;

	if (entry->event->meta == FUNC_TYPE_TINY)
		mode |= TRACE_MODE_TINY_MASK;

	if (analyzer && (analyzer->mode & mode) == mode &&
	    analyzer->analy_entry)
		return analyzer->analy_entry(trace, entry);

	return RESULT_CONT;
}

static int try_run_exit(trace_t *trace, analyzer_t *analyzer,
			analy_exit_t *exit)
{
	if (analyzer && (analyzer->mode & (1 << trace_ctx.mode)) &&
	    analyzer->analy_exit)
		return analyzer->analy_exit(trace, exit);

	return RESULT_CONT;
}

static inline void rule_run_ret(analy_entry_t *entry, trace_t *trace, int ret)
{
	bool hit = false;
	rule_t *rule;

	list_for_each_entry(rule, &trace->rules, list) {
		switch (rule->type) {
		case RULE_RETURN_ANY:
			hit = true;
			break;
		case RULE_RETURN_EQ:
			hit = rule->expected == ret;
			break;
		case RULE_RETURN_RANGE:
			hit = rule->range.min < ret && rule->range.max > ret;
			break;
		case RULE_RETURN_LT:
			hit = rule->expected < ret;
			break;
		case RULE_RETURN_GT:
			hit = rule->expected > ret;
			break;
		case RULE_RETURN_NE:
			hit = rule->expected != ret;
			break;
		default:
			continue;
		}
		if (!hit)
			continue;
		entry->rule = rule;
		if (!mode_has_context())
			break;
		switch (rule->level) {
		case RULE_INFO:
			break;
		case RULE_WARN:
			entry->ctx->status |= ANALY_CTX_WARN;
			break;
		case RULE_ERROR:
			entry->ctx->status |= ANALY_CTX_ERROR;
			break;
		}
		break;
	}
}

static inline void rule_run_any(analy_entry_t *entry, trace_t *trace)
{
	rule_t *rule;

	if (list_empty(&trace->rules))
		return;

	list_for_each_entry(rule, &trace->rules, list) {
		if (rule->type == RULE_RETURN_ANY) {
			entry->rule = rule;
			if (!mode_has_context())
				break;
			switch (rule->level) {
			case RULE_INFO:
				break;
			case RULE_WARN:
				entry->ctx->status |= ANALY_CTX_WARN;
				break;
			case RULE_ERROR:
				entry->ctx->status |= ANALY_CTX_ERROR;
				break;
			}
			break;
		}
	}
}

static int ctx_handle_ret(void *data, fake_analy_ctx_t *fctx)
{
	analyzer_t *analyzer;
	analy_entry_t *entry;
	analy_exit_t e = {
		.event = data,
	};
	trace_t *t;

	t = get_trace(e.event->func);
	entry = tracing_analy_exit(t, e.event, fctx);
	if (!entry) {
		pr_err("entry for exit not found: %x\n", e.event->key);
		return -ENOENT;
	}

	e.entry = entry;
	analyzer = t->analyzer;
	if (!analyzer || !(analyzer->mode & (1 << trace_ctx.mode)) ||
	    !analyzer->analy_exit)
		return 0;

	analyzer->analy_exit(t, &e);
	return 0;
}

void ctx_poll_handler(void *raw_ctx, void *data, u32 size)
{
	fake_analy_ctx_t *fctx;
	trace_t *trace = NULL;
	analy_entry_t *entry;
	analyzer_t *analyzer;
	event_t *e = data;
	analy_ctx_t *ctx;

	fctx = analy_fake_ctx_fetch(e->key);
	if (!fctx) {
		pr_err("analy context alloc failed\n");
		return;
	}
	ctx = fctx->ctx;

	if (func_get_type(data) == FUNC_TYPE_RET) {
		if (ctx_handle_ret(data, fctx))
			return;
		goto check_pending;
	}

	entry = analy_entry_alloc(data, size);
	if (!entry) {
		pr_err("entry alloc failed\n");
		return;
	}
	e = entry->event;
	pr_debug("create entry: %llx, %x\n", PTR2X(entry), e->key);

	trace = get_trace_from_analy_entry(entry);
	if (!trace) {
		pr_err("trace not found:%d\n", e->func);
		free(entry);
		put_fake_analy_ctx(fctx);
		goto check_pending;
	}

	entry->ctx = ctx;
	entry->fake_ctx = fctx;

	if (tracing_analy_entry(trace, entry))
		goto check_pending;

	/* run the trace analyzer */
	analyzer = trace->analyzer;
	if (try_run_entry(trace, analyzer, entry))
		goto check_pending;

	if (trace->status & TRACE_CFREE) {
		pr_debug("custom free hit %s\n", trace ? trace->name : "");
		put_fake_analy_ctx(fctx);
	}

	list_add_tail(&entry->list, &ctx->entries);
check_pending:
	if (ctx->refs <= 0) {
		pr_debug("ctx(%llx) finished with %s\n", PTR2X(ctx),
			 trace ? trace->name : "");
		analy_ctx_output(ctx);
	}
}

static inline bool trace_analyse_ret(trace_t *trace)
{
	return trace_ctx.mode == TRACE_MODE_MONITOR && trace_is_func(trace) &&
	       trace->monitor == TRACE_MONITOR_EXIT;
}

static inline void entry_basic_poll(analy_entry_t *entry)
{
	trace_t *trace;

	trace = get_trace_from_analy_entry(entry);
	try_run_entry(trace, trace->analyzer, entry);

	/* packet information is reported by FEXIT */
	if (trace_analyse_ret(trace)) {
		retevent_t rete = {
			.val = entry->event->retval,
		};
		analy_exit_t analy_exit = {
			.event = &rete,
			.entry = entry,
		};

		try_run_exit(trace, trace->analyzer, &analy_exit);
	}

	analy_entry_output(entry, NULL);
}

void basic_poll_handler(void *ctx, void *data, u32 size)
{
	analy_entry_t entry = {
		.event = data,
	};
	entry_basic_poll(&entry);
}

int stats_poll_handler()
{
	int map_fd = bpf_object__find_map_fd_by_name(trace_ctx.obj, "m_stats");
	char buf[128], *header, *unit;
	__u64 count[MAX_STATS_BUCKETS] = {};
	int i;

	if (!map_fd) {
		pr_err("failed to find BPF map m_stats\n");
		return -ENOTSUP;
	}

	if (trace_ctx.mode_mask & TRACE_MODE_RTT_MASK) {
		header = "rtt distribution:";
		unit = "ms";
	} else {
		header = "latency distribution:";
		unit = "us";
	}

	while (!trace_stopped()) {
		int start = 0, j;
		__u64 total = 0;

		for (i = 0; i < ARRAY_SIZE(count); i++) {
			bpf_map_lookup_elem(map_fd, &i, count + i);
			total += count[i];
		}

		pr_info("%-34s%llu\n", header, total);
		for (i = 0; i < ARRAY_SIZE(count); i++) {
			bool has_count = false;
			int p = 0, t = 0;

			/* check if there is data in the next bucket, used to terminate the output early */
			for (j = i; j < ARRAY_SIZE(count); j++) {
				if (count[j]) {
					has_count = true;
					break;
				}
			}

			if (!has_count && i > 8)
				break;

			if (i == LAST_STATS_BUCKET) {
				snprintf(buf, sizeof(buf), ">= %d%s", 1 << LAST_STATS_BUCKET, unit);
			} else {
				start = 1 << i;
				snprintf(buf, sizeof(buf), "%d - %5d%s",
				         start == 1 ? 0 : start,
				         (start << 1) - 1, unit);
			}

			if (total) {
				p = count[i] / total;
				t = (count[i] % total) * 10000 / total;
			}

			pr_info("%32s: %-8llu %d.%04d\n", buf, count[i], p, t);
		}
		sleep(1);
	}

	return 0;
}

int func_stats_poll_handler()
{
	int map_fd = bpf_object__find_map_fd_by_name(trace_ctx.obj, "m_stats");
	__u64 count;
	trace_t *t;
	int i;

	if (!map_fd) {
		pr_err("failed to find BPF map m_stats\n");
		return -ENOTSUP;
	}

	while (!trace_stopped()) {
		pr_info("function statistics:\n");
		for (i = 1; i < TRACE_MAX; i++) {
			bpf_map_lookup_elem(map_fd, &i, &count);

			if (!count)
				continue;
			t = get_trace(i);
			if (!t)
				continue;
			pr_info(" %-32s: %llu\n", t->name, count);
		}
		pr_info("\n");
		sleep(1);
	}

	return 0;
}

void latency_poll_handler(void *ctx, void *data, u32 size)
{
	analy_entry_t entry = {
		.event = data,
	};
	static char info[1024];
	u32 delta;

	delta = entry.event->latency;
	sprintf(info, " latency: %d.%03dms", delta / 1000,
		delta % 1000);
	entry_set_msg(&entry, info);
	analy_entry_output(&entry, NULL);
}

static void on_skb_free(fake_analy_ctx_t *fctx)
{
	if (mode_has_context())
		put_fake_analy_ctx(fctx);
}

DEFINE_ANALYZER_ENTRY(free, TRACE_MODE_CTX_MASK | TRACE_MODE_TINY_MASK)
{
	on_skb_free(e->fake_ctx);
	rule_run_any(e, trace);

	return RESULT_CONT;
}
enum skb_drop_reason_subsys {
	SKB_DROP_REASON_SUBSYS_CORE,
	SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE,
	SKB_DROP_REASON_SUBSYS_MAC80211_MONITOR,
	SKB_DROP_REASON_SUBSYS_OPENVSWITCH,
	SKB_DROP_REASON_SUBSYS_VXLAN,
	SKB_DROP_REASON_SUBSYS_NUM
};
const char *reason_subsys[] = {
	[SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE] = "MAC80211_UNUSABLE",
	[SKB_DROP_REASON_SUBSYS_MAC80211_MONITOR] = "MAC80211_MONITOR",
	[SKB_DROP_REASON_SUBSYS_OPENVSWITCH] = "OPENVSWITCH",
	[SKB_DROP_REASON_SUBSYS_VXLAN] = "VXLAN",
};

#define SKB_DROP_REASON_SUBSYS_MASK 0xffff0000
DEFINE_ANALYZER_ENTRY(drop, TRACE_MODE_ALL_MASK | TRACE_MODE_TINY_MASK)
{
	drop_event_t *event = (drop_event_t *)e->event;
	char *reason_str, *sym_str, *info, __reason[32];
	u32 reason = event->reason, subsys;
	struct sym_result *sym;

	on_skb_free(e->fake_ctx);
	if (e->event->meta == FUNC_TYPE_TINY)
		goto out;

	subsys = reason & SKB_DROP_REASON_SUBSYS_MASK;
	reason = reason & ~SKB_DROP_REASON_SUBSYS_MASK;
	if (subsys) {
		subsys >>= 16;
		if (subsys < SKB_DROP_REASON_SUBSYS_NUM)
			sprintf(__reason, "%s:%d", reason_subsys[subsys],
				reason);
		else
			sprintf(__reason, "%d:%d", subsys, reason);
		reason_str = __reason;
	} else {
		reason_str = get_drop_reason(reason);
		if (!reason_str) {
			sprintf(__reason, "%d", reason);
			reason_str = __reason;
		}
	}
	sym = sym_parse(event->location);
	sym_str = sym ? sym->desc : "unknow";

	info = malloc(1024);
	if (trace_ctx.drop_reason)
		sprintf_color(info, " *reason: %s, %s*", reason_str, sym_str);
	else
		sprintf_color(info, " *%s*", sym_str);
	entry_set_msg(e, info);

	rule_run_any(e, trace);
	if (!trace_mode_diag())
		goto out;

	/* generate the information in the analysis result part */
	info = malloc(1024);
	sprintf_color(info, "    location");
	sprintf_end(info, ":\n\t%s", sym_str);
	if (trace_ctx.drop_reason) {
		sprintf_end_color(info, "\n    drop reason");
		sprintf_end(info, ":\n\t%s", reason_str);
	}
	entry_set_extinfo(e, info);
out:
	return RESULT_CONT;
}

DEFINE_ANALYZER_ENTRY(reset, TRACE_MODE_ALL_MASK | TRACE_MODE_TINY_MASK)
{
	reset_event_t *event = (reset_event_t *)e->event;
	char *reason_str, *info, __reason[32];
	const char *state_str;
	unsigned char state = event->state;
	u32 reason = event->reason;

	if (e->event->meta == FUNC_TYPE_TINY)
		goto out;

	reason_str = get_reset_reason(reason);
	if (!reason_str) {
		sprintf(__reason, "%d", reason);
		reason_str = __reason;
	}

	info = malloc(1024);
	state_str = get_tcp_state_str(state);
	if (trace_ctx.reset_reason)
		sprintf_color(info, " *reason: %s, state: %s*", reason_str, state_str);
	else
		sprintf_color(info, " *state: %s*", state_str);
	entry_set_msg(e, info);

	rule_run_any(e, trace);
	if (!trace_mode_diag())
		goto out;

	/* generate the information in the analysis result part */
	info = malloc(1024);
	sprintf_color(info, "    state");
	sprintf_end(info, ":\n\t%s", state_str);
	if (trace_ctx.drop_reason) {
		sprintf_end_color(info, "\n    reset reason");
		sprintf_end(info, ":\n\t%s", reason_str);
	}
	entry_set_extinfo(e, info);
out:
	return RESULT_CONT;
}

DEFINE_ANALYZER_EXIT(clone, TRACE_MODE_CTX_MASK | TRACE_MODE_TINY_MASK)
{
	analy_entry_t *entry = e->entry;

	if (trace_ctx.args.traces_noclone)
		return RESULT_CONT;

	if (!entry || !e->event->val) {
		pr_err("skb clone failed\n");
		goto out;
	}

	pr_debug("clone analyzer triggered on: %llx\n", e->event->val);
	analy_fake_ctx_alloc((u32)e->event->val, entry->ctx);
	if (trace_mode_diag())
		rule_run_ret(entry, trace, 0);
out:
	return RESULT_CONSUME;
}

DEFINE_ANALYZER_EXIT(ret, TRACE_MODE_CTX_MASK | TRACE_MODE_TINY_MASK)
{
	int ret = (int) e->event->val;

	rule_run_ret(e->entry, trace, ret);
	return RESULT_CONT;
}

DEFINE_ANALYZER_ENTRY(default, TRACE_MODE_ALL_MASK)
{
	rule_run_any(e, trace);
	return RESULT_CONT;
}

const char *hook_names[][8] = {
	[NFPROTO_IPV4] = {
		[NF_INET_PRE_ROUTING]	= "PRE_ROUTING",
		[NF_INET_LOCAL_IN]	= "INPUT",
		[NF_INET_FORWARD]	= "FORWARD",
		[NF_INET_LOCAL_OUT]	= "OUTPUT",
		[NF_INET_POST_ROUTING]	= "POST_ROUTING",
		[NF_INET_NUMHOOKS]	= "NUMHOOKS",
	},
	[NFPROTO_BRIDGE] = {
		[NF_BR_PRE_ROUTING]	= "PRE_ROUTING",
		[NF_BR_LOCAL_IN]	= "INPUT",
		[NF_BR_FORWARD]		= "FORWARD",
		[NF_BR_LOCAL_OUT]	= "OUTPUT",
		[NF_BR_POST_ROUTING]	= "POST_ROUTING",
		[NF_BR_BROUTING]	= "BROUTING",
	},
	[NFPROTO_ARP] = {
		[NF_ARP_IN]	= "ARP_IN",
		[NF_ARP_OUT]	= "ARP_OUT",
		[NF_ARP_FORWARD]= "ARP_FORWARD",
	},
	[NFPROTO_IPV6] = {
		[NF_IP6_PRE_ROUTING]	= "PRE_ROUTING",
		[NF_IP6_LOCAL_IN]	= "INPUT",
		[NF_IP6_FORWARD]	= "FORWARD",
		[NF_IP6_LOCAL_OUT]	= "OUTPUT",
		[NF_IP6_POST_ROUTING]	= "POST_ROUTING",
		[NF_IP6_NUMHOOKS]	= "NUMHOOKS",
	},
	[NFPROTO_NUMPROTO] = {},
};
const char **inet_hook_names = hook_names[NFPROTO_IPV4];
const char *pf_names[] = {
	[NFPROTO_INET]		= "inet",
	[NFPROTO_IPV4]		= "ipv4",
	[NFPROTO_ARP]		= "arp",
	[NFPROTO_NETDEV]	= "netdev",
	[NFPROTO_BRIDGE]	= "bridge",
	[NFPROTO_IPV6]		= "ipv6",
	[NFPROTO_DECNET]	= "decnet",
	[NFPROTO_NUMPROTO]	= "invalid"
};
DEFINE_ANALYZER_ENTRY(nf, TRACE_MODE_ALL_MASK)
{
	nf_hooks_event_t *event = (nf_hooks_event_t *)e->event;
	char *msg = malloc(1024), *extinfo;
	struct sym_result *sym;
	int i = 0;

	msg[0] = '\0';
	if (event->pf > NFPROTO_NUMPROTO || event->hook > 7) {
		pr_err("invalid pf=%d and hook=%d received in netfilter\n",
		       (int)event->pf, (int)event->hook);
	} else {
	sprintf_color(msg, " *%s in chain: %s*", pf_names[event->pf],
		      hook_names[event->pf][event->hook]);
	}
	entry_set_msg(e, msg);

	if (!BPF_ARG_GET(hooks) || !e->status)
		goto out;

	extinfo = malloc(1024);
	sprintf(extinfo, "\n    following hook functions are blamed:\n");
	for (; i < ARRAY_SIZE(event->hooks); i++) {
		u64 hook = event->hooks[i];

		if (!hook)
			break;
		sym = sym_parse_exact(hook);
		if (sym)
			sprintf_end(extinfo, "\t%s\n", sym->name);
		else
			sprintf_end(extinfo, "\t%llx\n", hook);
	}
	entry_set_extinfo(e, extinfo);

out:
	return RESULT_CONT;
}
DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(nf)

DEFINE_ANALYZER_ENTRY(iptable, TRACE_MODE_ALL_MASK)
{
	nf_event_t *event = (nf_event_t *)e->event;
	char *msg = malloc(1024);
	const char *chain;

	msg[0] = '\0';
	if (event->chain[0] != '\0')
		chain = event->chain;
	else
		chain = inet_hook_names[event->hook];
	sprintf_color(msg, " *iptables table:%s, chain:%s*",
		      event->table, chain);
	entry_set_msg(e, msg);

	return RESULT_CONT;
}
DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(iptable)

DEFINE_ANALYZER_ENTRY(qdisc, TRACE_MODE_ALL_MASK)
{
	qdisc_event_t *event = (qdisc_event_t *)e->event;
	char *msg = malloc(1024);
	int hz;

	msg[0] = '\0';
	hz = kernel_hz();
	hz = hz > 0 ? hz : 1;
	sprintf_color(msg, " *qdisc state: %x, flags: %x, "
		      "last-update: %llums, len: %u*", event->state,
		      event->flags, (1000 * event->last_update) / hz,
		      event->qlen);
	entry_set_msg(e, msg);

	return RESULT_CONT;
}
DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(qdisc)

DEFINE_ANALYZER_ENTRY(rtt, TRACE_MODE_ALL_MASK)
{
	rtt_event_t *event = (rtt_event_t *)e->event;
	char *msg = malloc(1024);

	msg[0] = '\0';
	sprintf_color(msg, " *rtt:%u.%03ums, rtt_min:%u.%03ums*",
		      event->first_rtt / 1000, event->first_rtt % 1000,
		      event->last_rtt / 1000, event->last_rtt % 1000);
	entry_set_msg(e, msg);

	return RESULT_CONT;
}
DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(rtt)
