// SPDX-License-Identifier: MulanPSL-2.0

#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <unistd.h>
#undef __USE_MISC
#include <net/if.h>
#include <pthread.h>

#include <pkt_utils.h>
#include <stdlib.h>
#include <parse_sym.h>

#include "trace.h"
#include "analysis.h"
#include "dropreason.h"

#define CTX_HASH_LENGTH 1024
static struct hlist_head ctx_hash[CTX_HASH_LENGTH] = {};
const char *level_mark[] = {
	[RULE_INFO]  = PFMT_EMPH"NOTICE"PFMT_END,
	[RULE_WARN]  = PFMT_WARN"WARNING"PFMT_END,
	[RULE_ERROR] = PFMT_ERROR"ERROR"PFMT_END,
};
u32 ctx_count = 0;

static inline struct hlist_head *get_ctx_hash_head(u64 key)
{
	int index = (key >> 8) % CTX_HASH_LENGTH;
	return &ctx_hash[index];
}

static inline fake_analy_ctx_t *analy_fake_ctx_find(u64 key)
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
*analy_fake_ctx_alloc(u64 key, analy_ctx_t *ctx)
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
	pr_debug("fake ctx alloc: %llx, %llx\n", PTR2X(fake), key);
	return fake;
}

static fake_analy_ctx_t *analy_fake_ctx_fetch(u64 key)
{
	fake_analy_ctx_t *fake;
	analy_ctx_t *ctx;

	fake = analy_fake_ctx_find(key);
	if (fake)
		return fake;

	ctx = malloc(sizeof(analy_ctx_t));
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->entries);
	INIT_LIST_HEAD(&ctx->fakes);
	ctx->status = 0;
	ctx->refs = 0;

	fake = analy_fake_ctx_alloc(key, ctx);
	if (!fake)
		goto err;
	ctx_count++;

	return fake;
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

	if (entry->status & ANALY_ENTRY_ONCPU) {
		trace_t *t = get_trace_from_analy_entry(entry);
		list_del(&entry->cpu_list);
		pr_err("entry %s is still on cpu %d\n", t->name,
		       entry->cpu);
	}

	if (entry->status & ANALY_ENTRY_DLIST)
		free(container_of((void *)entry->event, data_list_t, data));
	else
		free(entry->event);
	free(entry);
}

static analy_entry_t *analy_entry_from_dlist(data_list_t *dlist)
{
	analy_entry_t *entry = calloc(1, sizeof(*entry));

	if (!entry)
		return NULL;

	entry->status |= ANALY_ENTRY_DLIST;
	entry->event = (void *)dlist->data;
	entry->cpu = dlist->cpu;
	return entry;
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
		detail_event_t *detail = (void *)e;
		static char ifbuf[IF_NAMESIZE];
		char *ifname = detail->ifname;

		if (ifname[0] == '\0') {
			ifname = if_indextoname(detail->ifindex, ifbuf);
			ifname = ifname ?: "";
		}

		sprintf(tinfo, "[%x][%-20s]%s[cpu:%-3u][%-5s][pid:%-7u][%-12s][ns:%u] ",
			detail->key, t->name, func_range, entry->cpu, ifname,
			detail->pid, detail->task, detail->netns);
	} else if (trace_ctx.mode != TRACE_MODE_DROP) {
		sprintf(tinfo, "[%-20s]%s ", t->name, func_range);
	}

	if (trace_using_sk(t))
		ts_print_sock(buf, &e->ske, tinfo, trace_ctx.args.date);
	else
		ts_print_packet(buf, &e->pkt, tinfo, trace_ctx.args.date);

	if ((entry->status & ANALY_ENTRY_RETURNED) && trace_ctx.args.ret)
		sprintf_end(buf, PFMT_EMPH_STR(" *return: %d*"),
			    (int)entry->priv);

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
		sprintf_end(buf, PFMT_EMPH_STR(" *%s*"), rule->msg);
		break;
	case RULE_WARN:
		sprintf_end(buf, PFMT_WARN_STR(" *%s*"), rule->msg);
		break;
	case RULE_ERROR:
		sprintf_end(buf, PFMT_ERROR_STR(" *%s*"), rule->msg);
		break;
	default:
		break;
	}
out:
	pr_info("%s\n", buf);

#ifdef __F_STACK_TRACE
	if (trace_is_stack(t) && e->meta != FUNC_TYPE_TINY)
		trace_ctx.ops->print_stack(e->stack_id);
#endif
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

	pr_info("---------------- "PFMT_EMPH_STR("ANALYSIS RESULT")
		" ---------------------\n");

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

		if (rule->adv)
			pr_info("    "PFMT_EMPH"fix advice"PFMT_END":\n\t%s\n",
				rule->adv);
		pr_info("\n");
	}

	if ((ctx->status & ANALY_CTX_ERROR) && !trace_ctx.args.intel_keep) {
		pr_info(PFMT_EMPH"analysis finished!"PFMT_END"\n");
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
	pr_info("*****************"PFMT_EMPH"%s "PFMT_END"***************\n",
		keys);
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

static void analy_dlist_add(struct list_head *head, data_list_t *data)
{
	u64 ts = ((event_t *)(void *)data->data)->pkt.ts;
	data_list_t *pos;

	list_for_each_entry_reverse(pos, head, list) {
		if (((event_t *)(void *)pos->data)->pkt.ts < ts) {
			list_add(&data->list, &pos->list);
			return;
		}
	}
	list_add(&data->list, head);
}

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static bool async_thread_created;
static pthread_t async_thread;
static LIST_HEAD(async_list);
typedef void (*async_cb)(data_list_t *dlist);
static void *async_poll_thread(void *arg)
{
	data_list_t *dlist, *pos;
	struct list_head head;
	async_cb cb = arg;

	while (!trace_ctx.stop) {
		pthread_mutex_lock(&mutex);
		INIT_LIST_HEAD(&head);
		list_splice_init(&async_list, &head);
		pthread_mutex_unlock(&mutex);

		list_for_each_entry_safe(dlist, pos, &head, list) {
			cb(dlist);
		}
		/* 0.1s */
		usleep(100000);
	}

	return NULL;
}

void do_async_poll(int cpu, void *data, u32 size, async_cb cb)
{
	data_list_t *dlist;

	dlist = malloc(sizeof(*dlist) + size);
	if (!dlist) {
		pr_err("data alloc failed\n");
		return;
	}
	memcpy(dlist->data, data, size);
	INIT_LIST_HEAD(&dlist->list);
	dlist->size = size;
	dlist->cpu = cpu;

	pthread_mutex_lock(&mutex);
	analy_dlist_add(&async_list, dlist);
	pthread_mutex_unlock(&mutex);

	if (!async_thread_created) {
		pthread_create(&async_thread, NULL, async_poll_thread, cb);
		async_thread_created = true;
	}
}

static int ctx_handle_ret(data_list_t *dlist, analy_ctx_t **analy_ctx)
{
	analy_exit_t analy_exit = {
		.event = *(retevent_t *)dlist->data,
		.cpu = dlist->cpu,
	};
	analyzer_t *analyzer;
	analy_entry_t *entry;
	trace_t *t;

	analyzer = trace_ctx.ops->analyzer;
	t = get_trace_from_analy_exit(&analy_exit);
	if (analyzer->analy_exit) {
		switch (analyzer->analy_exit(t, &analy_exit)) {
		case RESULT_CONSUME:
			return 1;
		case RESULT_CONT:
			break;
		default:
			break;
		}
	}
	entry = analy_exit.entry;
	if (!entry) {
		pr_err("entry for exit not found: %llx\n",
		       analy_exit.event.val);
		return -1;
	}

	analyzer = t->analyzer;
	*analy_ctx = entry->ctx;
	if (!analyzer || !(analyzer->mode & (1 << trace_ctx.mode)) ||
	    !analyzer->analy_exit)
		return 0;

	analyzer->analy_exit(t, &analy_exit);
	return 0;
}

static void ctx_poll_cb(data_list_t *dlist)
{
	fake_analy_ctx_t *fake;
	analy_ctx_t *analy_ctx;
	trace_t *trace = NULL;
	analy_entry_t *entry;
	analyzer_t *analyzer;
	event_t *e;

	analyzer = trace_ctx.ops->analyzer;
	if (func_get_type(dlist->data) == FUNC_TYPE_RET) {
		if (ctx_handle_ret(dlist, &analy_ctx))
			return;
		goto check_pending;
	}

	entry = analy_entry_from_dlist(dlist);
	if (!entry) {
		pr_err("entry alloc failed\n");
		return;
	}
	e = entry->event;
	pr_debug("create entry: %llx, %x, size: %u\n", PTR2X(entry),
		 e->key, dlist->size);

	fake = analy_fake_ctx_fetch(e->key);
	if (!fake) {
		pr_err("analy context alloc failed\n");
		return;
	}
	analy_ctx = fake->ctx;

	trace = get_trace_from_analy_entry(entry);
	if (!trace) {
		pr_err("trace not found:%d\n", e->func);
		free(entry);
		put_fake_analy_ctx(fake);
		goto check_pending;
	}

	entry->ctx = analy_ctx;
	entry->fake_ctx = fake;
	/* run the global analyzer */
	switch (try_run_entry(trace, analyzer, entry)) {
	case RESULT_CONSUME:
		goto check_pending;
	case RESULT_CONT:
		break;
	default:
		break;
	}

	/* run the trace analyzer */
	switch (try_run_entry(trace, trace->analyzer, entry)) {
	case RESULT_CONSUME:
		goto check_pending;
	case RESULT_CONT:
		break;
	default:
		break;
	}

	list_add_tail(&entry->list, &analy_ctx->entries);
check_pending:
	if (analy_ctx->refs <= 0) {
		pr_debug("ctx(%llx) finished with %s\n", PTR2X(analy_ctx),
			 trace ? trace->name : "");
		analy_ctx_output(analy_ctx);
	}
}

void ctx_poll_handler(void *raw_ctx, int cpu, void *data, u32 size)
{
	do_async_poll(cpu, data, size, ctx_poll_cb);
}

static inline bool trace_analyse_ret(trace_t *trace)
{
	return trace_ctx.mode == TRACE_MODE_MONITOR && trace_is_func(trace) &&
	       trace->monitor == TRACE_MONITOR_EXIT;
}

static inline void init_entry_from_data(analy_entry_t *entry,
					data_list_t *dlist)
{
	entry->event = (void *)dlist->data;
	entry->cpu = dlist->cpu;
}

static inline analy_entry_t *alloc_entry_from_data(data_list_t *dlist)
{
	analy_entry_t *entry = calloc(1, sizeof(*entry));

	if (!entry)
		return NULL;

	init_entry_from_data(entry, dlist);
	return entry;
}

static inline void entry_basic_poll(analy_entry_t *entry)
{
	trace_t *trace;

	trace = get_trace_from_analy_entry(entry);
	try_run_entry(trace, trace->analyzer, entry);

	if (trace_analyse_ret(trace)) {
		analy_exit_t analy_exit = {
			.event = {
				.val = entry->event->retval,
			},
			.entry = entry,
		};
		try_run_exit(trace, trace->analyzer, &analy_exit);
	}

	analy_entry_output(entry, NULL);
}

static void dlist_poll_cb(data_list_t *dlist)
{
	analy_entry_t entry = {};

	init_entry_from_data(&entry, dlist);
	entry_basic_poll(&entry);
	free(dlist);
}

void basic_poll_handler(void *ctx, int cpu, void *data, u32 size)
{
	analy_entry_t entry = {
		.event = data,
		.cpu = cpu
	};
	entry_basic_poll(&entry);
}

void async_poll_handler(void *ctx, int cpu, void *data, u32 size)
{
	do_async_poll(cpu, data, size, dlist_poll_cb);
}

int stats_poll_handler()
{
	int map_fd = bpf_object__find_map_fd_by_name(trace_ctx.obj, "m_stats");
	char buf[128], *header, *unit;
	__u64 count[16];
	
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

		for (i = 0; i < 16; i++) {
			bpf_map_lookup_elem(map_fd, &i, count + i);
			total += count[i];
		}

		pr_info("%-34s%llu\n", header, total);
		for (i = 0; i < 16; i++) {
			bool has_count = false;
			int p = 0, t = 0;

			for (j = i; j < 16; j++) {
				if (count[j])
					has_count = true;
			}

			if (!has_count && i > 8)
				break;

			start = 1 << i;
			sprintf(buf, "%d - %5d%s", start == 1 ? 0 : start,
				(start << 1) - 1, unit);
			if (total) {
				p = count[i] / total;
				t = (count[i] % total) * 10000 / total;
			}

			pr_info("%32s: %-8llu %d.%04d\n", buf, count[i],
				p, t);
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

void latency_poll_handler(void *ctx, int cpu, void *data, u32 size)
{
	analy_entry_t entry = {
		.event = data,
		.cpu = cpu,
	};
	static char info[1024];
	u32 delta;

	delta = entry.event->latency;
	sprintf(info, " latency: %d.%03dms", delta / 1000,
		delta % 1000);
	entry_set_msg(&entry, info);
	analy_entry_output(&entry, NULL);
}

DEFINE_ANALYZER_ENTRY(free, TRACE_MODE_CTX_MASK | TRACE_MODE_TINY_MASK)
{
	put_fake_analy_ctx(e->fake_ctx);
	hlist_del(&e->fake_ctx->hash);
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
	define_pure_event(drop_event_t, event, e->event);
	char *reason_str, *sym_str, *info, __reason[32];
	u32 reason = event->reason, subsys;
	struct sym_result *sym;

	if (mode_has_context()) {
		put_fake_analy_ctx(e->fake_ctx);
		hlist_del(&e->fake_ctx->hash);
	}

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
		sprintf(info, PFMT_EMPH_STR(" *reason: %s, %s*"), reason_str,
			sym_str);
	else
		sprintf(info, PFMT_EMPH_STR(" *%s*"), sym_str);
	entry_set_msg(e, info);

	rule_run_any(e, trace);
	if (!trace_mode_diag())
		goto out;

	/* generate the information in the analysis result part */
	info = malloc(1024);
	sprintf(info, PFMT_EMPH_STR("    location")":\n\t%s", sym_str);
	if (trace_ctx.drop_reason) {
		sprintf_end(info, PFMT_EMPH_STR("\n    drop reason")":\n\t%s",
			    reason_str);
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

	if (!entry || !e->event.val) {
		pr_err("skb clone failed\n");
		goto out;
	}

	pr_debug("clone analyzer triggered on: %llx\n", e->event.val);
	analy_fake_ctx_alloc(e->event.val, entry->ctx);
	if (trace_mode_diag())
		rule_run_ret(entry, trace, 0);
out:
	return RESULT_CONSUME;
}

DEFINE_ANALYZER_EXIT(ret, TRACE_MODE_CTX_MASK | TRACE_MODE_TINY_MASK)
{
	int ret = (int) e->event.val;

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
	define_pure_event(nf_hooks_event_t, event, e->event);
	char *msg = malloc(1024), *extinfo;
	struct sym_result *sym;
	int i = 0;

	msg[0] = '\0';
	if (event->pf > NFPROTO_NUMPROTO || event->hook > 7) {
		pr_err("invalid pf=%d and hook=%d received in netfilter\n",
		       (int)event->pf, (int)event->hook);
	} else {
		sprintf(msg, PFMT_EMPH_STR(" *%s in chain: %s*"),
			pf_names[event->pf],
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
	define_pure_event(nf_event_t, event, e->event);
	char *msg = malloc(1024);
	const char *chain;

	msg[0] = '\0';
	if (event->chain[0] != '\0')
		chain = event->chain;
	else
		chain = inet_hook_names[event->hook];
	sprintf(msg, PFMT_EMPH_STR(" *iptables table:%s, chain:%s*"),
		event->table, chain);
	entry_set_msg(e, msg);

	return RESULT_CONT;
}
DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(iptable)

DEFINE_ANALYZER_ENTRY(qdisc, TRACE_MODE_ALL_MASK)
{
	define_pure_event(qdisc_event_t, event, e->event);
	char *msg = malloc(1024);
	int hz;

	msg[0] = '\0';
	hz = kernel_hz();
	hz = hz > 0 ? hz : 1;
	sprintf(msg, PFMT_EMPH_STR(" *qdisc state: %x, flags: %x, "
		"last-update: %llums, len: %u*"), event->state,
		event->flags, (1000 * event->last_update) / hz,
		event->qlen);
	entry_set_msg(e, msg);

	return RESULT_CONT;
}
DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(qdisc)

DEFINE_ANALYZER_ENTRY(rtt, TRACE_MODE_ALL_MASK)
{
	define_pure_event(rtt_event_t, event, e->event);
	char *msg = malloc(1024);

	msg[0] = '\0';
	sprintf(msg, PFMT_EMPH_STR(" *rtt:%ums, rtt_min:%ums*"),
		event->first_rtt, event->last_rtt);
	entry_set_msg(e, msg);

	return RESULT_CONT;
}
DEFINE_ANALYZER_EXIT_FUNC_DEFAULT(rtt)
