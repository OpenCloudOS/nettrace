#include <packet.h>

typedef struct {
	u64	location;
	packet_t pkt;
	u16 reason;
} event_t;
