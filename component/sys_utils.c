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

static int __hz = -1;
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

int kernel_get_config(char *name, char *output)
{
	char tmp[128] = {};
	int err;

	if (file_exist("/proc/config.gz"))
		err = execf(tmp, "zcat /proc/config.gz | grep 'CONFIG_%s=' 2>&1",
			    name);
	else
		err = execf(tmp, "grep 'CONFIG_%s=' /boot/config-$(uname -r)"
			    " 2>&1", name);

	if (!output || err)
		return err;

	sscanf(tmp, "%*[^=]=%s", output);
	return err;
}

bool kernel_has_config(char *name)
{
	char type[32] = {};
	return kernel_get_config(name, type) == 0 && type[0] == 'y';
}

int kernel_hz()
{
	char hz[32] = {};
	int err;

	if (__hz > 0)
		return __hz;

	err = kernel_get_config("HZ", hz);
	if (err)
		return -ENOTSUP;

	__hz = atoi(hz);
	return __hz;
}

u32 file_inode(char *path)
{
	char tmp1[128], tmp2[128];
	struct stat file_stat;
	char *__path = path;
	u32 inode;

	if (!file_exist(path))
		return 0;

again:
	if (sscanf(__path, "%*[^:]:[%u]", &inode) == 1)
		return inode;

	if (stat(__path, &file_stat) == -1)
		return 0;

	if (S_ISLNK(file_stat.st_mode)) {
		if (readlink(path, tmp1, sizeof(tmp1)) == -1)
			return 0;
		memcpy(tmp2, tmp1, sizeof(tmp1));
		__path = tmp2;
		goto again;
	}

	return file_stat.st_ino;
}
