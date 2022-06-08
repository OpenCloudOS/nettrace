#ifndef _H_SYS_UTILS
#define _H_SYS_UTILS

#include <stdlib.h>

extern int log_level;

int execf(char *output, char *fmt, ...);
int exec(char *cmd, char *output);

static inline int simple_exec(char *cmd)
{
	return exec(cmd, NULL);
}

#define pr_level(level, fmt, args...)	\
do {					\
	if (level <= log_level)		\
		printf(fmt, ##args);	\
} while (0)

#define pr_info(fmt, args...)	pr_level(0, fmt, ##args)
#define pr_verb(fmt, args...)	pr_level(1, fmt, ##args)
#define pr_warn(fmt, args...)	pr_level(1, "\033[0;34mWARN: "fmt"\033[0m", ##args)
#define pr_err(fmt, args...)	pr_level(0, "\033[0;31mERROR: "fmt"\033[0m", ##args)
#define pr_debug(fmt, args...)	pr_level(2, "DEBUG: "fmt, ##args)

#define PFMT_EMPH	"\033[0;33m"
#define PFMT_END	"\033[0m"

#define set_log_level(l)	log_level = l

#define sprintf_end(buf, fmt, args...)	\
	sprintf(strlen(buf) + buf, fmt, ##args)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif
