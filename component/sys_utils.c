// SPDX-License-Identifier: MulanPSL-2.0

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include "sys_utils.h"

int log_level = 0;

int exec(char *cmd, char *output)
{
	FILE *f = popen(cmd, "r");
	char buf[128];
	int status;

	if (output)
		output[0] = '\0';

	while (fgets(buf, sizeof(buf) - 1, f) != NULL) {
		if (!output)
			continue;
		strcat(output + strlen(output), buf);
	}

	status = pclose(f);
	pr_debug("command: %s, status:%d\n", cmd, WEXITSTATUS(status));
	return WEXITSTATUS(status);
}

int execf(char *output, char *fmt, ...)
{
	static char cmd[1024];
	va_list valist;

	va_start(valist, fmt);
	vsprintf(cmd, fmt, valist);
	va_end(valist);

	return exec(cmd, output);
}

int liberate_l()
{
	struct rlimit lim = {RLIM_INFINITY, RLIM_INFINITY};
	return setrlimit(RLIMIT_MEMLOCK, &lim);
}

bool fsearch(FILE *f, char *target)
{
	char tmp[128];

	while (fscanf(f, "%s", tmp) == 1) {
		if (strstr(tmp, target))
			return true;
	}
	return false;
}

int kernel_version()
{
	int major, minor, patch;
	struct utsname buf;

	uname(&buf);
	sscanf(buf.release, "%d.%d.%d", &major, &minor, &patch);

	return kv_to_num(major, minor, patch);
}

bool debugfs_mounted()
{
	return simple_exec("mount | grep debugfs") == 0;
}

bool kernel_has_config(char *name)
{
	return execf(NULL, "zgrep 'CONFIG_%s=y' /proc/config.gz 2>/dev/null",
		     name) == 0;
}
