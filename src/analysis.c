// SPDX-License-Identifier: MulanPSL-2.0

#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_bridge.h>
#undef __USE_MISC
#include <net/if.h>

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
static u32 ctx_count = 0;

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

static analy_entry_t *analy_entry_alloc(void *data, u32 size)
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

	free(entry->event);
	free(entry);
}

static void analy_entry_handle(analy_entry_t *entry)
{
	packet_t *pkt = &entry->event->pkt;
	static char buf[1024], tinfo[256];
	event_t *e = entry->event;
	rule_t *rule;
	trace_t *t;

	t = get_trace_from_analy_entry(entry);
	pr_debug("output entry(%llx)\n", PTR2X(entry));
	if (trace_ctx.detail) {
		detail_event_t *detail = (void *)e;
		static char ifbuf[IF_NAMESIZE];
		char *ifname = detail->ifname;

		if (ifname[0] == '\0') {
			ifname = if_indextoname(detail->ifindex, ifbuf);
			ifname = ifname ?: "";
		}

		sprintf(tinfo, "[%llx][%-20s][cpu:%-3u][%-5s][pid:%-7u][%-12s] ",
			detail->key, t->name, entry->cpu, ifname,
			detail->pid, detail->task);
	} else if (trace_ctx.mode != TRACE_MODE_DROP) {
		sprintf(tinfo, "[%-20s] ", t->name);
	}

	ts_print_packet(buf, pkt, tinfo, trace_ctx.args.date);

	if (trace_ctx.mode == TRACE_MODE_BASIC)
		goto out;

	if ((entry->status & ANALY_ENTRY_RETURNED) && trace_ctx.args.ret)
		sprintf_end(buf, PFMT_EMPH_STR(" *return: %d*"),
			    (int)entry->priv);

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
	if (trace_is_stack(t))
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

void analy_ctx_handle(analy_ctx_t *ctx)
{
	analy_entry_t *entry, *n;
	static char keys[1024];
	fake_analy_ctx_t *fake;
	rule_t *rule = NULL;
	trace_t *trace;
	int i = 0;

	if (trace_mode_intel() && trace_ctx.args.intel_quiet &&
	    !ctx->status)
		goto free_ctx;

	keys[0] = '\0';
	list_for_each_entry(fake, &ctx->fakes, list)
		sprintf_end(keys, ",%llx", fake->key);

	keys[0] = ' ';
	pr_info("*****************"PFMT_EMPH"%s "PFMT_END"***************\n",
		keys);
	list_for_each_entry(entry, &ctx->entries, list)
		analy_entry_handle(entry);

	if (trace_mode_intel())
		pr_info("---------------- "PFMT_EMPH_STR("ANALYSIS RESULT")
			" ---------------------\n");
	else
		goto out;

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
out:
	pr_info("\n");
free_ctx:
	analy_ctx_free(ctx);
}

static int try_run_analyzer(trace_t *trace, analyzer_t *analyzer,
			    analy_entry_t *entry)
{
	if (analyzer && (analyzer->mode & (1 << trace_ctx.mode)) &&
	    analyzer->analy_entry)
		return analyzer->analy_entry(trace, entry);

	return RESULT_CONT;
}

void tl_poll_handler(void *raw_ctx, int cpu, void *data, u32 size)
{
	static char buf[1024], tinfo[128];
	fake_analy_ctx_t *fake;
	analy_ctx_t *analy_ctx;
	analy_entry_t *entry;
	analyzer_t *analyzer;
	trace_t *trace;
	event_t *e;

	analyzer = trace_ctx.ops->analyzer;
	if (event_is_ret(size))
		goto do_ret;

	entry = analy_entry_alloc(data, size);
	if (!entry) {
		pr_err("entry alloc failed\n");
		return;
	}
	e = entry->event;
	entry->cpu = cpu;
	pr_debug("create entry: %llx, %llx\n", PTR2X(entry), e->key);

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
	switch (try_run_analyzer(trace, analyzer, entry)) {
	case RESULT_CONSUME:
		goto check_pending;
	case RESULT_CONT:
		break;
	default:
		break;
	}

	switch (try_run_analyzer(trace, trace->analyzer, entry)) {
	case RESULT_CONSUME:
		goto check_pending;
	case RESULT_CONT:
		break;
	default:
		break;
	}

	list_add_tail(&entry->list, &analy_ctx->entries);
	goto check_pending;

do_ret:;
	analy_exit_t analy_exit = {
		.event = *(retevent_t *)data,
		.cpu = cpu,
	};
	trace = get_trace_from_analy_exit(&analy_exit);
	if (analyzer->analy_exit) {
		switch (analyzer->analy_exit(trace, &analy_exit)) {
		case RESULT_CONSUME:
			return;
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
		return;
	}

	analyzer = trace->analyzer;
	analy_ctx = entry->ctx;
	if (!analyzer || !(analyzer->mode & (1 << trace_ctx.mode)) ||
	    !analyzer->analy_exit)
		goto check_pending;

	switch (analyzer->analy_exit(trace, &analy_exit)) {
	case RESULT_CONSUME:
		return;
	case RESULT_CONT:
		break;
	default:
		break;
	}

check_pending:
	if (analy_ctx->refs <= 0) {
		pr_debug("ctx(%llx) finished with %s\n", PTR2X(analy_ctx),
			 trace->name);
		analy_ctx_handle(analy_ctx);
	}
}

void basic_poll_handler(void *ctx, int cpu, void *data, u32 size)
{
	analy_entry_t entry = {
		.event = data,
		.cpu = cpu
	};
	trace_t *trace;

	trace = get_trace_from_analy_entry(&entry);
	try_run_analyzer(trace, trace->analyzer, &entry);
	analy_entry_handle(&entry);
}

static inline void rule_run(analy_entry_t *entry, trace_t *trace, int ret)
{
	bool hit = false;
	rule_t *rule;

	list_for_each_entry(rule, &trace->rules, list) {
		switch (rule->type) {
		case RULE_RETURN_ANY:
			hit = true;
			break;
		case RULE_RETURN_EQ:
			hit =rule->expected == ret;
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

DEFINE_ANALYZER_ENTRY(free, TRACE_MODE_TIMELINE_MASK | TRACE_MODE_INETL_MASK)
{
	put_fake_analy_ctx(e->fake_ctx);
	hlist_del(&e->fake_ctx->hash);
	if (!trace_mode_intel())
		goto out;

	rule_run(e, trace, 0);
out:
	return RESULT_CONT;
}

DEFINE_ANALYZER_ENTRY(drop, TRACE_MODE_TIMELINE_MASK | TRACE_MODE_INETL_MASK |
			    TRACE_MODE_DROP_MASK)
{
	drop_event_t *event = (void *)e->event;
	char *reason = NULL, *sym_str, *info;
	struct sym_result *sym;

	reason = get_drop_reason(event->reason);
	sym = sym_parse(event->location);
	sym_str = sym ? sym->desc : "unknow";

	info = malloc(1024);
	info[0] = '\0';
	if (trace_ctx.mode == TRACE_MODE_DROP) {
		if (trace_ctx.drop_reason)
			sprintf(info, ", reason: %s, %s", reason, sym_str);
		else
			sprintf(info, ", %s", sym_str);
		entry_set_msg(e, info);
		goto out;
	}

	put_fake_analy_ctx(e->fake_ctx);
	hlist_del(&e->fake_ctx->hash);
	if (!trace_mode_intel())
		goto out;

	rule_run(e, trace, 0);
	sprintf(info, PFMT_EMPH_STR("    location")":\n\t%s", sym_str);
	if (trace_ctx.drop_reason) {
		sprintf_end(info, PFMT_EMPH_STR("\n    drop reason")":\n\t%s",
			    reason ?: "unknow");
	}
	entry_set_extinfo(e, info);
out:
	return RESULT_CONT;
}

DEFINE_ANALYZER_EXIT(clone, TRACE_MODE_TIMELINE_MASK | TRACE_MODE_INETL_MASK)
{
	analy_entry_t *entry = e->entry;

	if (!entry || !e->event.val) {
		pr_err("skb clone failed\n");
		goto out;
	}

	pr_debug("clone analyzer triggered on: %llx\n", e->event.val);
	analy_fake_ctx_alloc(e->event.val, entry->ctx);
	if (trace_mode_intel())
		rule_run(entry, trace, 0);
out:
	return RESULT_CONSUME;
}

DEFINE_ANALYZER_EXIT(ret, TRACE_MODE_INETL_MASK)
{
	int ret = (int) e->event.val;

	rule_run(e->entry, trace, ret);
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
	}
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
};
DEFINE_ANALYZER_EXIT(nf, TRACE_MODE_INETL_MASK)
{
	analy_entry_t *entry = e->entry;
	nf_hooks_event_t *event = (void *)entry->event;
	char *msg = malloc(1024), *extinfo;
	struct sym_result *sym;
	int i = 0;

	msg[0] = '\0';
	sprintf(msg, PFMT_EMPH_STR(" *%s in chain: %s*"), pf_names[event->pf],
		hook_names[event->pf][event->hook]);
	entry_set_msg(entry, msg);
	rule_run(entry, trace, e->event.val);

	if (!BPF_ARG_GET(hooks) || !entry->status)
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
	entry_set_extinfo(entry, extinfo);

out:
	return RESULT_CONT;
}

DEFINE_ANALYZER_EXIT(iptable, TRACE_MODE_INETL_MASK)
{
	analy_entry_t *entry = e->entry;
	nf_event_t *event = (void *)entry->event;
	char *msg = malloc(1024);
	const char *chain;

	msg[0] = '\0';
	if (event->chain[0] != '\0')
		chain = event->chain;
	else
		chain = inet_hook_names[event->hook];
	sprintf(msg, PFMT_EMPH_STR(" *iptables table:%s, chain:%s*"),
		event->table, chain);
	entry_set_msg(entry, msg);
	rule_run(entry, trace, e->event.val);

	return RESULT_CONT;
}

DEFINE_ANALYZER_EXIT(qdisc, TRACE_MODE_INETL_MASK)
{
	qdisc_event_t *event = (void *)e->entry->event;
	char *msg = malloc(1024);

	msg[0] = '\0';
	sprintf(msg, PFMT_EMPH_STR(" *queue state: %x, flags: %x, len: %lu*"),
		event->state, event->flags, event->qlen);
	entry_set_msg(e->entry, msg);

	rule_run(e->entry, trace, e->event.val);

	return RESULT_CONT;
}
