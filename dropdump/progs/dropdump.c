#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <skb_utils.h>

#include "shared.h"

PARAM_DEFINE_UINT(u16, reason);
PARAM_DEFINE_UINT(u32, limit);
PARAM_DEFINE_UINT(u32, limit_bucket);

PARAM_DEFINE_BOOL(snmp_mode, false);

u32 snmp_reasons[SKB_DROP_REASON_MAX];
int current_budget = 1024;
u64 last_ts = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 64);
} m_event SEC(".maps");

#define EVENT_OUTPUT(ctx, data)					\
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,	\
			      &(data), sizeof(data))

static inline void do_snmp(u16 reason)
{
	if (reason >= SKB_DROP_REASON_MAX)
		return;
	snmp_reasons[reason]++;
}

static __always_inline bool is_limited(u64 ts)
{
	if (current_budget) {
		current_budget--;
		return false;
	}

	u64 dela = ((ts - last_ts) / 1000) * arg_limit / 1000000;
	if (dela) {
		if (dela > arg_limit_bucket)
			dela = arg_limit_bucket;
		current_budget = dela - 1;
		return false;
	}
	return true;
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(trace_kfree_skb, struct sk_buff *skb, void *location,
	     int reason)
{
	if (PARAM_CHECK_BOOL(snmp_mode)) {
		do_snmp((__u16)reason);
		goto out;
	}

	if (PARAM_CHECK_ENABLE(reason, reason))
		goto out;

	event_t event = { .reason = reason };
	if (probe_parse_skb(skb, &event.pkt))
		goto out;

	event.pkt.ts = bpf_ktime_get_ns();
	if (PARAM_ENABLED(limit) && is_limited(event.pkt.ts))
		goto out;

	event.location = (u64)location;
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
out:
	return 0;
}

char _license[] SEC("license") = "GPL";