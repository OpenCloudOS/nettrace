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

struct kfree_skb_args {
	u64 pad;
	void *skb;
	void *location;
	unsigned short protocol;
	int reason;
};

static inline void do_snmp(int reason)
{
	if (reason >= SKB_DROP_REASON_MAX || reason < 0)
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

char _license[] SEC("license") = "GPL";
