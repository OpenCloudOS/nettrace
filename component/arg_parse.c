// SPDX-License-Identifier: MulanPSL-2.0

#include <getopt.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#define _LINUX_IN_H
#include <netinet/in.h>
#include <arpa/inet.h>

#include "arg_parse.h"
#include "net_utils.h"

#define KEY_START	1000

#define for_each_opt(i, options, item, option_size)	\
	for (i = 0, item = options; i < option_size;	\
	     i++, item = options + i)			\

int parse_args(int argc, char *argv[], arg_config_t *config,
	       option_item_t *options,
	       int option_size)
{
	int i, cur_opt, size, err = 0;
	struct option *long_opts;
	int cur_key = KEY_START;
	char sopts[128] = {};
	option_item_t *item;
	struct option *opt;

	opt = long_opts = calloc(option_size + 1, sizeof(struct option));
	if (!long_opts)
		return -ENOMEM;

	for_each_opt(i, options, item, option_size) {
		int val = item->sname;
		bool has_s = val;

		if (item->type == OPTION_BLANK)
			continue;
		if (!has_s)
			val = cur_key++;
		item->key = val;

		switch (item->type) {
		case OPTION_BOOL_REV:
		case OPTION_BOOL:
		case OPTION_HELP:
			if (has_s)
				sprintf_end(sopts, "%c", item->sname);
			opt->has_arg = no_argument;
			break;
		default:
			if (has_s)
				sprintf_end(sopts, "%c:", item->sname);
			opt->has_arg = required_argument;
			break;
		}
		if (!item->lname)
			continue;
		opt->name = item->lname;
		opt->flag = NULL;
		opt->val = val;
		opt++;
	}

#define S_DST(type, val) *((type *)item->dest) = val
#define S_SET(type, val)				\
	do {						\
		if (item->set)				\
			*((type *)item->set) = val;	\
		item->__is_set = true;			\
	} while (0)

	while ((cur_opt = getopt_long(argc, argv, sopts, long_opts,
				      NULL)) != -1) {
		for_each_opt(i, options, item, option_size) {
			if (item->key == cur_opt)
				goto found;
		}
		goto err;
found:
		switch (item->type) {
		case OPTION_BOOL:
			S_DST(bool, true);
			S_SET(bool, true);
			break;
		case OPTION_BOOL_REV:
			S_DST(bool, false);
			S_SET(bool, true);
			break;
		case OPTION_STRING:
			S_DST(char *, optarg);
			S_SET(bool, true);
			break;
		case OPTION_INT: {
			int val = atoi(optarg);
			S_DST(int, val);
			S_SET(bool, true);
			break;
		}
		case OPTION_U16BE:
		case OPTION_U16: {
			int val = atoi(optarg);
			if (val <=0 || val > 65535) {
				printf("invalid arg value: %s\n",
				       optarg);
				goto err;
			}
			if (item->type == OPTION_U16BE)
				val = htons(val);
			S_DST(u16, val);
			S_SET(bool, true);
			break;
		}
		case OPTION_U32: {
			int val = atoi(optarg);
			if (val < 0) {
				printf("invalid arg value: %s\n",
				       optarg);
				goto err;
			}
			S_DST(u32, val);
			S_SET(bool, true);
			break;
		}
		case OPTION_IPV4:
			if (!inet_pton(AF_INET, optarg, item->dest)) {
				printf("invalid ip address: %s\n", optarg);
				goto err;
			}
			S_SET(bool, true);
			break;
		case OPTION_IPV6:
			if (!inet_pton(AF_INET6, optarg, item->dest)) {
				printf("invalid ip address: %s\n", optarg);
				goto err;
			}
			S_SET(bool, true);
			break;
		case OPTION_IPV4ORIPV6:
			if (inet_pton(AF_INET, optarg, item->dest)) {
				S_SET(u16, ETH_P_IP);
			} else if (inet_pton(AF_INET6, optarg, item->dest)) {
				S_SET(u16, ETH_P_IPV6);
			} else {
				printf("invalid ip address: %s\n", optarg);
				goto err;
			}
			break;
		case OPTION_HELP:
			goto help;
		case OPTION_PROTO: {
			/* convert string to number in host order */
			int val, layer = proto2i(optarg, &val);
			if (!layer) {
				printf("protocol not found\n");
				goto err;
			}
			S_SET(int, layer);
			S_DST(u16, val);
			break;
		}
		default:
			printf("invalid argument\n");
			goto err;
		}
	}

	for_each_opt(i, options, item, option_size) {
		if (item->required && !item->__is_set) {
			if (item->sname)
				printf("-%c is necessary\n", item->sname);
			else
				printf("--%s is necessary\n", item->lname);
			goto err;
		}
	}

	free(long_opts);
	return 0;
err:
	return -EINVAL;
help:
	printf("%s: %s\n", config->name, config->summary);
	printf("\nUsage:\n");
	for_each_opt(i, options, item, option_size) {
		char name[64];
		if (item->type == OPTION_BLANK) {
			printf("\n");
			continue;
		}
		if (item->sname && item->lname)
			sprintf(name, "-%c, --%s", item->sname, item->lname);
		else if (item->sname)
			sprintf(name, "-%c", item->sname);
		else
			sprintf(name, "--%s", item->lname);
		printf("    %-16s %s\n", name, item->desc);
	}
	free(long_opts);
	exit(0);
}
