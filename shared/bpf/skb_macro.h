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

#define ETH_HLEN	14		/* Total octets in header.	 */

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#endif

#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129

/* Codes for EXT_ECHO (PROBE) */
#define ICMPV6_EXT_ECHO_REQUEST		160
#define ICMPV6_EXT_ECHO_REPLY		161

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

#ifdef COMPAT_MODE
#undef bpf_core_type_exists
#define bpf_core_type_exists(type) false

#undef bpf_core_field_exists
#define bpf_core_field_exists(field) false

#undef bpf_core_enum_value_exists
#define bpf_core_enum_value_exists(value) false
#endif

#endif
