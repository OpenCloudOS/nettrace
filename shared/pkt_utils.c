#include <linux/icmp.h>
#include <time.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <sys/sysinfo.h>
#define _LINUX_IN_H
#include <netinet/in.h>

#include "pkt_utils.h"

static time_t time_offset;
static struct tm *convert_ts_to_date(u64 ts)
{
	struct tm *p;
	time_t tmp;

	if (!time_offset) {
		struct sysinfo s_info;
		sysinfo(&s_info);

		time(&time_offset);
		time_offset -= s_info.uptime;
	}

	tmp = time_offset + (ts / 1000000000);
	return localtime(&tmp);
}

int ts_print_packet(char *buf, packet_t *pkt, char *minfo,
		    bool date_format)
{
	static char saddr[MAX_ADDR_LENGTH], daddr[MAX_ADDR_LENGTH];
	u64 ts = pkt->ts;
	struct tm *p;
	u8 flags, l4;
	int pos = 0;

	if (date_format) {
		p = convert_ts_to_date(ts);
		BUF_FMT("[%d-%d-%d %02d:%02d:%02d.%06d] ", 1900 + p->tm_year,
			1 + p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min,
			p->tm_sec, ts % 1000000000 / 1000);
	} else {
		BUF_FMT("[%llu.%06llu] ", ts / 1000000000,
			ts % 1000000000 / 1000);
	}

	if (minfo)
		BUF_FMT("%s", minfo);

	if (!pkt->proto_l3) {
		BUF_FMT("unknow");
		goto out;
	}

	switch (pkt->proto_l3) {
	case ETH_P_IP:
		i2ip(saddr, pkt->l3.ipv4.saddr);
		i2ip(daddr, pkt->l3.ipv4.daddr);
		goto print_ip;
	case ETH_P_IPV6:
		i2ipv6(saddr, pkt->l3.ipv6.saddr);
		i2ipv6(daddr, pkt->l3.ipv6.daddr);
		goto print_ip;
	case ETH_P_ARP:
		goto print_arp;
	default:
		break;
	}

	BUF_FMT("ether protocol: %u", pkt->proto_l3);
	goto out;

print_ip:
	l4 = pkt->proto_l4;
	BUF_FMT("%s: ", i2l4(l4));
	switch (l4) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		BUF_FMT("%s:%d -> %s:%d",
			saddr, htons(pkt->l4.min.sport),
			daddr, htons(pkt->l4.min.dport));
		break;
	case IPPROTO_ICMP:
		BUF_FMT("%s -> %s", saddr, daddr);
		break;
	default:
		BUF_FMT("%s -> %s", saddr, daddr);
		goto out;
	}

	switch (l4) {
	case IPPROTO_TCP:
		flags = pkt->l4.tcp.flags;
#define CONVERT_FLAG(mask, name) ((flags & mask) ? name : "")
		BUF_FMT(" seq:%u, ack:%u, flags:%s%s%s%s",
			pkt->l4.tcp.seq,
			pkt->l4.tcp.ack,
			CONVERT_FLAG(TCP_FLAGS_SYN, "S"),
			CONVERT_FLAG(TCP_FLAGS_ACK, "A"),
			CONVERT_FLAG(TCP_FLAGS_RST, "R"),
			CONVERT_FLAG(TCP_FLAGS_PSH, "P"));
		break;
	case IPPROTO_ICMP:
		switch (pkt->l4.icmp.type) {
		default:
			BUF_FMT(" type: %u, code: %u, ", pkt->l4.icmp.type,
				pkt->l4.icmp.code);
			break;
		case ICMP_ECHO:
			BUF_FMT(" ping request, ");
			break;
		case ICMP_ECHOREPLY:
			BUF_FMT(" ping reply, ");
			break;
		}
		BUF_FMT("seq: %u", ntohs(pkt->l4.icmp.seq));
		break;
	default:
		break;
	}
	goto out;

print_arp:
out:
	return 0;
}

int base_print_packet(char *buf, packet_t *pkt)
{
	return ts_print_packet(buf, pkt, NULL, false);
}
