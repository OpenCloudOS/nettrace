
#define COMMON_PROG_ARGS(args)					\
	{							\
		.lname = "saddr",				\
		.sname = 's',					\
		.dest = &(args)->saddr,				\
		.type = OPTION_IPV4,				\
		.set = &(args)->enable_saddr,			\
		.desc = "filter source ip address",		\
	},							\
	{							\
		.lname = "saddr6",				\
		.dest = &(args)->saddr_v6,			\
		.type = OPTION_IPV6,				\
		.set = &(args)->enable_saddr_v6,		\
		.desc = "filter source ip v6 address",		\
	},							\
	{							\
		.lname = "daddr",				\
		.sname = 'd',					\
		.dest = &(args)->daddr,				\
		.type = OPTION_IPV4,				\
		.set = &(args)->enable_daddr,			\
		.desc = "filter dest ip address",		\
	},							\
	{							\
		.lname = "daddr6",				\
		.dest = &(args)->daddr_v6,			\
		.type = OPTION_IPV6,				\
		.set = &(args)->enable_daddr_v6,		\
		.desc = "filter dest ip v6 address",		\
	},							\
	{							\
		.lname = "addr",				\
		.dest = &(args)->addr,				\
		.type = OPTION_IPV4,				\
		.set = &(args)->enable_addr,			\
		.desc = "filter source or dest ip address",	\
	},							\
	{							\
		.lname = "addr6",				\
		.dest = &(args)->addr_v6,			\
		.type = OPTION_IPV6,				\
		.set = &(args)->enable_addr_v6,			\
		.desc = "filter source or dest ip v6 address",	\
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
