#ifndef _H_NET_UTILS
#define _H_NET_UTILS

#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <asm-generic/int-ll64.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>

typedef __s8  s8;
typedef __u8  u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

static inline void i2ip(char *dest, __u32 ip)
{
	u8 *t = (u8 *)&ip;
	sprintf(dest, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);
}

static inline int ip2i(char *ip, __u32 *dest)
{
	u8 *c = (u8 *)dest;
	u32 t[4] = {};

	if (sscanf(ip, "%u.%u.%u.%u", t, t + 1, t + 2, t + 3) != 4)
		return -EINVAL;

#define C(index) c[index] = t[index] 
	C(0);
	C(1);
	C(2);
	C(3);
#undef C
	return 0;
}

int proto2i(char *proto, int *dest);

#endif