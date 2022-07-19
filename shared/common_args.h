
#define COMMON_PROG_ARGS()					\
	{							\
		.lname = "saddr",				\
		.sname = 's',					\
		.dest = R(saddr),				\
		.type = OPTION_IPV4,				\
		.set = E(saddr),				\
		.desc = "filter source ip address",		\
	},							\
	{							\
		.lname = "daddr",				\
		.sname = 'd',					\
		.dest = R(daddr),				\
		.type = OPTION_IPV4,				\
		.set = E(daddr),				\
		.desc = "filter dest ip address",		\
	},							\
	{							\
		.lname = "addr",				\
		.dest = R(addr),				\
		.type = OPTION_IPV4,				\
		.set = E(addr),					\
		.desc = "filter source or dest ip address",	\
	},							\
	{							\
		.lname = "sport",				\
		.sname = 'S',					\
		.dest = R(sport),				\
		.type = OPTION_U16BE,				\
		.set = E(sport),				\
		.desc = "filter source TCP/UDP port",		\
	},							\
	{							\
		.lname = "dport",				\
		.sname = 'D',					\
		.dest = R(dport),				\
		.type = OPTION_U16BE,				\
		.set = E(dport),				\
		.desc = "filter dest TCP/UDP port",		\
	},							\
	{							\
		.lname = "port",				\
		.sname = 'P',					\
		.dest = R(port),				\
		.type = OPTION_U16BE,				\
		.set = E(port),					\
		.desc = "filter source or dest TCP/UDP port",	\
	},							\
	{							\
		.lname = "proto",				\
		.sname = 'p',					\
		.dest = &proto,					\
		.type = OPTION_PROTO,				\
		.set = &proto_l,				\
		.desc = "filter L3/L4 protocol, such as 'tcp', 'arp'",	\
	},

COMMON_PROG_ARGS()