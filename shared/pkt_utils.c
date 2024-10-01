#include <linux/icmp.h>
#include <time.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <sys/sysinfo.h>
#include <linux/icmpv6.h>
#define _LINUX_IN_H
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <sys_utils.h>

#include "pkt_utils.h"

static time_t time_offset;
static struct tm *convert_ts_to_date(u64 ts)
{
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

int ts_print_ts(char *buf, u64 ts, bool date_format)
{
	struct tm *p;

	if (date_format) {
		p = convert_ts_to_date(ts);
		return sprintf(buf, "[%d-%d-%d %02d:%02d:%02d.%06lld] ", 1900 + p->tm_year,
			       1 + p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min,
			       p->tm_sec, ts % 1000000000 / 1000);
	} else {
		return sprintf(buf, "[%llu.%06llu] ", ts / 1000000000,
			       ts % 1000000000 / 1000);
	}
}

static void ntomac(u8 mac[], char *dst)
{
	for (int i = 0; i < 6; i++) {
		sprintf(dst + (i * 3), "%02X", mac[i]);  
		if (i < 5)
			dst[(i * 3) + 2] = ':';
	}
}

void ts_print_packet(char *buf, packet_t *pkt, char *minfo,
		     bool date_format)
{
	static char saddr[MAX_ADDR_LENGTH], daddr[MAX_ADDR_LENGTH];
	char *l4_desc;
	u8 flags, l4;
	int pos;

	pos = ts_print_ts(buf, pkt->ts, date_format);
	if (minfo)
		BUF_FMT("%s", minfo);

	if (!pkt->proto_l3) {
		BUF_FMT("unknow");
		return;
	}

	switch (pkt->proto_l3) {
	case ETH_P_ARP:
	case ETH_P_IP:
		inet_ntop(AF_INET, (void *)&pkt->l3.ipv4.saddr, saddr,
			  sizeof(saddr));
		inet_ntop(AF_INET, (void *)&pkt->l3.ipv4.daddr, daddr,
			  sizeof(daddr));

		if (pkt->proto_l3 == ETH_P_IP)
			break;

		if (pkt->l4.arp_ext.op == ARPOP_REPLY) {
			static char mac[MAX_ADDR_LENGTH];

			ntomac(pkt->l4.arp_ext.source, mac);
			BUF_FMT("ARP: %s is at %s", saddr, mac);
		} else {
			BUF_FMT("ARP: who has %s, tell %s", daddr, saddr);
		}
		return;
#ifndef NT_DISABLE_IPV6
	case ETH_P_IPV6:
		inet_ntop(AF_INET6, (void *)pkt->l3.ipv6.saddr, saddr,
			  sizeof(saddr));
		inet_ntop(AF_INET6, (void *)pkt->l3.ipv6.daddr, daddr,
			  sizeof(daddr));
		break;
#endif
	default:
		BUF_FMT("ether protocol: 0x%04x", pkt->proto_l3);
		return;
	}

	l4 = pkt->proto_l4;
	l4_desc = i2l4(l4);
	if (l4_desc)
		BUF_FMT("%s: ", l4_desc);
	else
		BUF_FMT("%d: ", l4);

	switch (l4) {
	case IPPROTO_IP:
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		BUF_FMT("%s:%d -> %s:%d",
			saddr, ntohs(pkt->l4.min.sport),
			daddr, ntohs(pkt->l4.min.dport));
		break;
	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
	case IPPROTO_ESP:
		BUF_FMT("%s -> %s", saddr, daddr);
		break;
	default:
		BUF_FMT("%s -> %s", saddr, daddr);
		return;
	}

	switch (l4) {
	case IPPROTO_IP:
	case IPPROTO_TCP:
		flags = pkt->l4.tcp.flags;
#define CONVERT_FLAG(mask, name) ((flags & mask) ? name : "")
		BUF_FMT(" seq:%u, ack:%u, flags:%s%s%s%s%s",
			pkt->l4.tcp.seq,
			pkt->l4.tcp.ack,
			CONVERT_FLAG(TCP_FLAGS_SYN, "S"),
			CONVERT_FLAG(TCP_FLAGS_ACK, "A"),
			CONVERT_FLAG(TCP_FLAGS_RST, "R"),
			CONVERT_FLAG(TCP_FLAGS_PSH, "P"),
			CONVERT_FLAG(TCP_FLAGS_FIN, "F"));
		break;
	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
		switch (pkt->l4.icmp.type) {
		default:
			BUF_FMT(" type: %u, code: %u, ", pkt->l4.icmp.type,
				pkt->l4.icmp.code);
			break;
		case ICMPV6_ECHO_REQUEST:
		case ICMP_ECHO:
			BUF_FMT(" ping request, ");
			break;
		case ICMPV6_EXT_ECHO_REQUEST:
			BUF_FMT(" ping request(ext), ");
			break;
		case ICMPV6_ECHO_REPLY:
		case ICMP_ECHOREPLY:
			BUF_FMT(" ping reply, ");
			break;
		case ICMPV6_EXT_ECHO_REPLY:
			BUF_FMT(" ping reply(ext), ");
			break;
		}
		BUF_FMT("seq: %u, id: %u", ntohs(pkt->l4.icmp.seq),
			ntohs(pkt->l4.icmp.id));
		break;
	case IPPROTO_ESP:
		BUF_FMT(" spi:0x%x seq:0x%x", ntohl(pkt->l4.espheader.spi),
			ntohl(pkt->l4.espheader.seq));
		break;
	default:
		break;
	}
}

static const char *timer_name[] = {
	[ICSK_TIME_RETRANS] = "retrans",
	[ICSK_TIME_DACK] = "dack",
	[ICSK_TIME_PROBE0] = "probe0",
	[ICSK_TIME_EARLY_RETRANS] = "early_retrans",
	[ICSK_TIME_LOSS_PROBE] = "loss_probe",
	[ICSK_TIME_REO_TIMEOUT] = "reo_timeout",
};
static const char *state_name[] = {
	[0] = "UNKNOW",
	[TCP_ESTABLISHED] = "ESTABLISHED",
	[TCP_SYN_SENT] = "SYN_SENT",
	[TCP_SYN_RECV] = "SYN_RECV",
	[TCP_FIN_WAIT1] = "FIN_WAIT1",
	[TCP_FIN_WAIT2] = "FIN_WAIT2",
	[TCP_TIME_WAIT] = "TIME_WAIT",
	[TCP_CLOSE] = "CLOSE",
	[TCP_CLOSE_WAIT] = "CLOSE_WAIT",
	[TCP_LAST_ACK] = "LAST_ACK",
	[TCP_LISTEN] = "LISTEN",
	[TCP_CLOSING] = "CLOSING",
};
static const char *ca_name[] = {
	[TCP_CA_Open] = "CA_Open",
	[TCP_CA_Disorder] = "CA_Disorder",
	[TCP_CA_CWR] = "CA_CWR",
	[TCP_CA_Recovery] = "CA_Recovery",
	[TCP_CA_Loss] = "CA_Loss",
};

typedef struct {
	u8	icsk_ca_state:5,
		icsk_ca_initialized:1,
		icsk_ca_setsockopt:1,
		icsk_ca_dst_locked:1;

} tcp_ca_data_t;

void ts_print_sock(char *buf, sock_t *ske, char *minfo, bool date_format)
{
	static char saddr[MAX_ADDR_LENGTH], daddr[MAX_ADDR_LENGTH];
	u64 ts = ske->ts;
	int pos = 0, hz;
	struct tm *p;
	u8 l4;

	if (date_format) {
		p = convert_ts_to_date(ts);
		BUF_FMT("[%d-%d-%d %02d:%02d:%02d.%06lld] ", 1900 + p->tm_year,
			1 + p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min,
			p->tm_sec, ts % 1000000000 / 1000);
	} else {
		BUF_FMT("[%llu.%06llu] ", ts / 1000000000,
			ts % 1000000000 / 1000);
	}

	if (minfo)
		BUF_FMT("%s", minfo);

	if (!ske->proto_l3) {
		BUF_FMT("unknow");
		return;
	}

	switch (ske->proto_l3) {
	case ETH_P_IP:
		inet_ntop(AF_INET, (void *)&ske->l3.ipv4.saddr, saddr,
			  sizeof(saddr));
		inet_ntop(AF_INET, (void *)&ske->l3.ipv4.daddr, daddr,
			  sizeof(daddr));
		break;
	case ETH_P_IPV6:
		sprintf(saddr, "ipv6");
		sprintf(daddr, "ipv6");
		break;
#if 0
	case ETH_P_IPV6:
		inet_ntop(AF_INET6, (void *)ske->l3.ipv6.saddr, saddr,
			  sizeof(saddr));
		inet_ntop(AF_INET6, (void *)ske->l3.ipv6.daddr, daddr,
			  sizeof(daddr));
		goto print_l4;
#endif
	default:
		BUF_FMT("ether protocol: %u", ske->proto_l3);
		return;
	}

	l4 = ske->proto_l4;
	BUF_FMT("%s: ", i2l4(l4));
	switch (l4) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		BUF_FMT("%s:%d -> %s:%d",
			saddr, ntohs(ske->l4.min.sport),
			daddr, ntohs(ske->l4.min.dport));
		break;
	default:
		BUF_FMT("%s -> %s", saddr, daddr);
		return;
	}

	switch (l4) {
	case IPPROTO_TCP: {
		tcp_ca_data_t *ca_state = (void *)&ske->ca_state;
		BUF_FMT(" %s %s out:(p%u r%u) unack:%u", state_name[ske->state],
			ca_name[ca_state->icsk_ca_state],
			ske->l4.tcp.packets_out,
			ske->l4.tcp.retrans_out,
			ske->l4.tcp.snd_una);
	}
	case IPPROTO_UDP:
		hz = kernel_hz();
		hz = hz > 0 ? hz : 1;
		BUF_FMT(" mem:(w%u r%u)", ske->wqlen, ske->rqlen);
		if (ske->timer_pending)
			BUF_FMT(" timer:(%s, %u.%03us)",
				timer_name[ske->timer_pending],
				ske->timer_out / hz,
				((ske->timer_out * 1000) / hz) % 1000);
		break;
	default:
		break;
	}
}
