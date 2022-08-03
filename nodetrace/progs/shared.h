#ifndef _H_SHARED
#define _H_SHARED

#include <packet.h>

typedef struct {
	packet_t pkt;
	__u8 location;
} event_t;

enum {
	LOCALTION_INGRESS,
	LOCALTION_EGRESS,
	LOCALTION_MARK,
	LOCALTION_ERR,
};

struct bpf_args {
	pkt_args_t pkt;
	bool quiet;
};
typedef struct bpf_args bpf_args_t;

#endif
