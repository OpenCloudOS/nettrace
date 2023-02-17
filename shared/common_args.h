
#define COMMON_PROG_ARGS_BEGIN()				\
	u8 addr_buf[16], saddr_buf[16], daddr_buf[16];		\
	u16 addr_pf = 0, saddr_pf = 0, daddr_pf = 0;		\
	int proto_l = 0;					\
	u16 proto;

#define COMMON_PROG_ARGS_DEFINE(args)				\
	{							\
		.lname = "saddr",				\
		.sname = 's',					\
		.dest = saddr_buf,				\
		.type = OPTION_IPV4ORIPV6,			\
		.set = &saddr_pf,				\
		.desc = "filter source ip/ipv6 address",	\
	},							\
	{							\
		.lname = "daddr",				\
		.sname = 'd',					\
		.dest = daddr_buf,				\
		.type = OPTION_IPV4ORIPV6,			\
		.set = &daddr_pf,				\
		.desc = "filter dest ip/ipv6 address",		\
	},							\
	{							\
		.lname = "addr",				\
		.dest = addr_buf,				\
		.type = OPTION_IPV4ORIPV6,			\
		.set = &addr_pf,				\
		.desc = "filter source or dest ip/ipv6 address",	\
	},							\
	{							\
		.lname = "sport",				\
		.sname = 'S',					\
		.dest = &(args)->sport,				\
		.type = OPTION_U16BE,				\
		.set = &(args)->enable_sport,			\
		.desc = "filter source TCP/UDP port",		\
	},							\
	{							\
		.lname = "dport",				\
		.sname = 'D',					\
		.dest = &(args)->dport,				\
		.type = OPTION_U16BE,				\
		.set = &(args)->enable_dport,			\
		.desc = "filter dest TCP/UDP port",		\
	},							\
	{							\
		.lname = "port",				\
		.sname = 'P',					\
		.dest = &(args)->port,				\
		.type = OPTION_U16BE,				\
		.set = &(args)->enable_port,			\
		.desc = "filter source or dest TCP/UDP port",	\
	},							\
	{							\
		.lname = "proto",				\
		.sname = 'p',					\
		.dest = &proto,					\
		.type = OPTION_PROTO,				\
		.set = &proto_l,				\
		.desc = "filter L3/L4 protocol, such as 'tcp', 'arp'",	\
	}

/* convert the args to the eBPF pkt_arg struct */
#define FILL_ADDR_PROTO(name, subfix, args, pf) if (name##_pf == pf) {	\
	memcpy(&(args)->name##subfix, name##_buf,			\
	       sizeof((args)->name##subfix));				\
	(args)->enable_##name##subfix = true;				\
	if ((args)->enable_l3_proto && (args)->l3_proto != pf) { 	\
		pr_err("ip" #subfix " protocol is excepted!\n");	\
		goto err;						\
	}								\
	(args)->enable_l3_proto = true;					\
	(args)->l3_proto = pf;						\
}
#define FILL_ADDR(name, args)					\
	FILL_ADDR_PROTO(name, _v6, args, ETH_P_IPV6)		\
	FILL_ADDR_PROTO(name, , args, ETH_P_IP)

#define COMMON_PROG_ARGS_END(args)		\
	switch (proto_l) {			\
	case 3:					\
		(args)->enable_l3_proto = true;	\
		(args)->l3_proto = proto;	\
		break;				\
	case 4:					\
		(args)->enable_l4_proto = true;	\
		(args)->l4_proto = proto;	\
		break;				\
	default:				\
		break;				\
	}					\
	FILL_ADDR(saddr, args)			\
	FILL_ADDR(daddr, args)			\
	FILL_ADDR(addr, args)
