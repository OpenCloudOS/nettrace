// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_SYS_UTILS
#define _H_SYS_UTILS

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include "net_utils.h"

extern int log_level;

int	execf(char *output, char *fmt, ...);
int	exec(char *cmd, char *output);
int	liberate_l();
bool	fsearch(FILE *f, char *target);
int	kernel_version();
bool	debugfs_mounted();
bool	kernel_has_config(char *name);
int	kernel_hz();
u32	file_inode(char *path);

static inline int simple_exec(char *cmd)
{
	return exec(cmd, NULL);
}

static inline bool file_exist(const char *path)
{
	return access(path, F_OK) == 0;
}

static inline int kv_to_num(int major, int minor, int patch)
{
	return (major << 16) + (minor << 8) + patch;
}

/* compare current kernel version with the provided one */
static inline int kv_compare(int major, int minor, int patch)
{
	return kernel_version() - kv_to_num(major, minor, patch);
}

#define pr_level(level, target, fmt, args...)	\
do {						\
	if (level <= log_level)			\
		fprintf(target, fmt, ##args);	\
} while (0)

#define pr_info(fmt, args...)	pr_level(0, stdout, fmt, ##args)
#define pr_verb(fmt, args...)	pr_level(1, stdout, fmt, ##args)
#define pr_warn(fmt, args...)	pr_level(0, stderr, "\033[0;34mWARN: "fmt"\033[0m", ##args)
#define pr_err(fmt, args...)	pr_level(0, stderr, "\033[0;31mERROR: "fmt"\033[0m", ##args)
#define pr_debug(fmt, args...)	pr_level(2, stdout, "DEBUG: "fmt, ##args)

#define PFMT_EMPH	"\033[0;33m"
#define PFMT_WARN	"\033[0;32m"
#define PFMT_ERROR	"\033[0;31m"
#define PFMT_END	"\033[0m"

#define PFMT_EMPH_STR(str)	PFMT_EMPH str PFMT_END
#define PFMT_WARN_STR(str)	PFMT_WARN str PFMT_END
#define PFMT_ERROR_STR(str)	PFMT_ERROR str PFMT_END

#define set_log_level(l)	log_level = l

#define sprintf_end(buf, fmt, args...)	\
	sprintf(strlen(buf) + buf, fmt, ##args)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define MIN(a, b) (a > b ? b : a)
#define MAX(a, b) (a > b ? a : b)

#define PTR2X(ptr)	(__u64)(void *)ptr

#endif
