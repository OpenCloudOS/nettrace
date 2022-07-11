// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_SYS_UTILS
#define _H_SYS_UTILS

#include <stdlib.h>

extern int log_level;

int execf(char *output, char *fmt, ...);
int exec(char *cmd, char *output);
int liberate_l();

static inline int simple_exec(char *cmd)
{
	return exec(cmd, NULL);
}

#define pr_level(level, target, fmt, args...)	\
do {						\
	if (level <= log_level)			\
		fprintf(target, fmt, ##args);	\
} while (0)

#define pr_info(fmt, args...)	pr_level(0, stdout, fmt, ##args)
#define pr_verb(fmt, args...)	pr_level(1, stdout, fmt, ##args)
#define pr_warn(fmt, args...)	pr_level(1, stderr, "\033[0;34mWARN: "fmt"\033[0m", ##args)
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

#endif
