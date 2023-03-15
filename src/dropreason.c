#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys_utils.h>

#include "dropreason.h"

#define REASON_MAX_COUNT	256
#define REASON_MAX_LEN		32

static char drop_reasons[REASON_MAX_COUNT][REASON_MAX_LEN] = {};
static int drop_reason_max;
static bool drop_reason_inited = false;

/* check if drop reason on kfree_skb is supported */
bool drop_reason_support()
{
	return simple_exec("cat /sys/kernel/debug/tracing/events/skb/"
			   "kfree_skb/format 2>/dev/null | "
			   "grep NOT_SPECIFIED") == 0;
}

static int parse_reason_enum()
{
	char name[REASON_MAX_LEN], tmp[128];
	int index = 0, pos;
	FILE *f;

	f = fopen("/sys/kernel/debug/tracing/events/skb/kfree_skb/format",
		 "r");

	if (!f || !fsearch(f, "__print_symbolic")) {
		if (f)
			fclose(f);
		return -1;
	}

	while (true) {
		if (!fsearch(f, "{") ||
		    fscanf(f, "%d, \"%31[A-Z_]", &index, name) != 2)
			break;
		strcpy(drop_reasons[index], name);
	}
	drop_reason_max = index;
	drop_reason_inited = true;

	fclose(f);
	return 0;
}

char *get_drop_reason(int index)
{
	if (!drop_reason_inited && parse_reason_enum())
		return NULL;
	if (index <= 0 || index > drop_reason_max)
		return "unknown";

	return drop_reasons[index];
}
