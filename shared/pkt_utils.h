#ifndef _H_PKT_UTILS
#define _H_PKT_UTILS

#include <net_utils.h>
#include <packet.h>

#define MAX_ADDR_LENGTH		48
#define PARAM_SET(name, value)			\
	obj->rodata->enable_##name = true;	\
	obj->rodata->arg_##name = value

#define BUF_FMT_INIT(fmt, args...)			\
	do {						\
		pos = sprintf(buf, fmt, ##args);	\
	} while (0)

#define BUF_FMT(fmt, args...) pos += sprintf(buf + pos, fmt, ##args);

int ts_print_packet(char *buf, packet_t *pkt, char *minfo);
int base_print_packet(char *buf, packet_t *pkt);

#endif