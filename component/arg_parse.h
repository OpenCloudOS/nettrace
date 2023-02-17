// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_ARG_PARSE
#define _H_ARG_PARSE
#include <stdbool.h>

#include "sys_utils.h"

enum option_type {
	OPTION_STRING,
	OPTION_BOOL,
	OPTION_BOOL_REV,
	OPTION_U16,
	OPTION_U16BE,
	OPTION_U32,
	OPTION_INT,
	OPTION_IPV4,
	OPTION_IPV6,
	OPTION_IPV4ORIPV6,
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

int parse_args(int argc, char *argv[], arg_config_t *config,
	       option_item_t *options,
	       int option_size);

#endif