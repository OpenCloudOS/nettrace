#ifndef _H_ARG_PARSE
#define _H_ARG_PARSE
#include <stdbool.h>

enum option_type {
	OPTION_STRING,
	OPTION_BOOL,
	OPTION_BOOL_REV,
	OPTION_U16,
	OPTION_U32,
	OPTION_INT,
	OPTION_IPV4,
	OPTION_HELP,
	OPTION_BLANK,
	OPTION_PROTO,
};

typedef struct {
	char	*lname;
	char	sname;
	void	*dest;
	enum option_type type;
	void	*set;
	char	*desc;
	bool	required;
	int	key;
	bool	__is_set;
} option_item_t;

typedef struct {
	char *summary;
	char *name;
	char *desc;
} arg_config_t;

#define sprintf_end(buf, fmt, args...)	\
	sprintf(strlen(sopts) + sopts, fmt, ##args)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int parse_args(int argc, char *argv[], arg_config_t *config,
	       option_item_t *options,
	       int option_size);

#endif