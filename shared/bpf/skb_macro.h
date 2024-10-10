/* 
 * This file define the macro that used by BPF program. As the vmlinux
 * can't contain macro definition, we have to define them is this
 * file instead.
 * 
 * NOTE: This file SHOULD be used by BPF only.
 */
#ifndef _H_BPF_MACRO
#define _H_BPF_MACRO

#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/

#define ETH_HLEN	14		/* Total octets in header.	 */

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#endif

#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7

#ifndef NULL
#define NULL (void *)0
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/* redefine all the CO-RE usage if BTF not supported */
#ifdef NO_BTF
#undef bpf_core_type_exists
#define bpf_core_type_exists(type) false

#undef bpf_core_field_exists
#define bpf_core_field_exists(field...) false

#undef bpf_core_enum_value_exists
#define bpf_core_enum_value_exists(value) false

#undef bpf_core_field_offset
#define bpf_core_field_offset(type, field) offsetof(type, field)
#endif

#ifdef __F_NO_PROBE_READ_STR
#define bpf_probe_read_str bpf_probe_read
#endif

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

#ifndef READ_ONCE
#define READ_ONCE(x)		(*(volatile typeof(x) *)&x)
#define WRITE_ONCE(x, v)	(*(volatile typeof(x) *)&x) = (v)
#endif

#endif
