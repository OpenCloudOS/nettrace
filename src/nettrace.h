// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_NETTRACE
#define _H_NETTRACE

#include <pkt_utils.h>

#define pr_version()		_pr_version(VERSION, RELEASE)
#define _pr_version(v, r)	__pr_version(v, r)
#define __pr_version(v, r)	pr_info("version: "#v#r"\n")

#endif
