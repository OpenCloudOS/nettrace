// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_NETTRACE
#define _H_NETTRACE

#include "output.h"

#define pr_version()							\
	pr_info("version: " macro_to_str(VERSION) macro_to_str(RELEASE)	\
		nt_ternary_take(INLINE_MODE, ", inline", "")		\
		nt_ternary_take(NO_BTF, ", no-btf, kernel-"		\
				macro_to_str(__KERN_VER), " btf")	\
		nt_ternary_take(BPF_NO_GLOBAL_DATA, ", no-global-data",	\
				", global-data")			\
		nt_ternary_take(NT_DISABLE_IPV6, ", no-ipv6", "")	\
		"\n")

#endif
