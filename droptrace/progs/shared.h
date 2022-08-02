#include <packet.h>

typedef struct {
	u64	location;
	packet_t pkt;
	u16 reason;
} event_t;

struct bpf_args {
	pkt_args_t pkt;
	u16 reason;
	bool enable_reason;
	u32 limit;
	bool enable_limit;
	u32 limit_bucket;
	bool enable_limit_bucket;
	bool snmp_mode;
	u32 snmp_reasons[SKB_DROP_REASON_MAX];
	int current_budget;
	u64 last_ts;
};
typedef struct bpf_args bpf_args_t;
