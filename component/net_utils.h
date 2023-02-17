// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_NET_UTILS
#define _H_NET_UTILS

#include <unistd.h>
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

extern char *l4_proto_names[];

static inline char *i2l4(u8 num)
{
	return l4_proto_names[num];
}

int proto2i(char *proto, int *dest);

#endif