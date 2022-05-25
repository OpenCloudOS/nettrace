
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
