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
#include <bpf/bpf.h>

#include <net_utils.h>
#include <arg_parse.h>
#include <pkt_utils.h>

#include "progs/shared.h"
#include <bpf_utils.h>

static inline int tc_attach(int prog_fd, char *nic, char *pref,
			    bool ingress)
{
	char cmd[256], path_pin[256] = "/sys/fs/bpf/tc_tmp", *filter;

	if (bpf_obj_pin(prog_fd, path_pin)) {
		printf("failed to pin mark\n");
		goto err;
	}

	filter = ingress ? "ingress": "egress";
	sprintf(cmd, "((tc qdisc show dev %s | grep clsact > /dev/null) || "
		"tc qdisc add dev %s clsact) && "
		"tc filter add dev %s %s bpf object-pinned %s;"
		"rm %s",
		nic, nic, nic, filter, path_pin, path_pin);

	if (simple_exec(cmd)) {
		pr_err("failed to attach eBPF program\n");
		goto err;
	}

	/* get the filter entry that we added. 'pref' of it can be used
	 * to delete it later.
	 */
	if (execf(pref, "tc filter show dev %s %s | grep tc_tmp |"
		  " tail -n 1 | awk '{print $5}'", nic,
		  filter))
		pr_warn("failed to query pref of tc\n");

	return 0;
err:
	return -1;
}

static inline void tc_detach(char *nic, char *pref, bool ingress)
{
	char cmd[128], *filter;

	filter = ingress ? "ingress": "egress";
	snprintf(cmd, sizeof(cmd) - 1,
		 "tc filter delete dev %s %s pref %s",
		 nic, filter,
		 pref);

	if (simple_exec(cmd))
		pr_warn("failed to detach tc: %s\n", cmd);
}
