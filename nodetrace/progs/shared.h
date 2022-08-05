#ifndef _H_SHARED
#define _H_SHARED

#include <skb_shared.h>

#define DEFINE_BPF_ARGS()	\
	bool quiet

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

#endif
