#include "pkt_utils.h"

int base_print_packet(char *buf, packet_t *pkt)
{
	char saddr[MAX_ADDR_LENGTH], daddr[MAX_ADDR_LENGTH];
	int pos = 0;
	u8 flags;
	u64 ts;

	ts = pkt->ts;
	if (ts)
		BUF_FMT("[%lu.%06lu] ", ts / 1000000000,
			ts % 1000000000 / 1000);

	if (!pkt->proto_l3) {
		BUF_FMT("unknow");
		goto out;
	}

	switch (pkt->proto_l3) {
	case ETH_P_IP:
		goto print_ip;
	case ETH_P_ARP:
		goto print_arp;
	default:
		break;
	}

	BUF_FMT("ether protocol: %u\n", pkt->proto_l3);
	goto out;

print_ip:
	i2ip(saddr, pkt->l3.ipv4.saddr);
	i2ip(daddr, pkt->l3.ipv4.daddr);

	switch (pkt->proto_l4) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		BUF_FMT("%s:%d -> %s:%d",
			saddr, htons(pkt->l4.min.sport),
			daddr, htons(pkt->l4.min.dport));
		break;
	default:
		BUF_FMT("%s -> %s, protocol: %u\n", saddr, daddr,
			pkt->proto_l4);
		goto out;
	}

	switch (pkt->proto_l4) {
	case IPPROTO_TCP:
		flags = pkt->l4.tcp.flags;
#define CONVERT_FLAG(mask, name) ((flags & mask) ? name : "")
		BUF_FMT(" TCP seq:%u, ack:%u, flags:%s%s%s%s",
			pkt->l4.tcp.seq,
			pkt->l4.tcp.ack,
			CONVERT_FLAG(TCP_FLAGS_SYN, "S"),
			CONVERT_FLAG(TCP_FLAGS_ACK, "A"),
			CONVERT_FLAG(TCP_FLAGS_RST, "R"),
			CONVERT_FLAG(TCP_FLAGS_PSH, "P"));
		break;
	case IPPROTO_UDP:
		BUF_FMT(" UDP");
		break;
	default:
		break;
	}
	goto out;

print_arp:
out:
	return 0;
}