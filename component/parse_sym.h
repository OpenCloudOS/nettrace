// SPDX-License-Identifier: MulanPSL-2.0

#include <asm-generic/int-ll64.h>
#include <stdbool.h>
#include <stdlib.h>

#define MAX_SYM_LENGTH		128
#define MAX_SYM_ADDR_LENGTH	(MAX_SYM_LENGTH + 8)

enum {
	SYM_NOT_EXIST,
	SYM_MODULE,
	SYM_KERNEL
};

struct sym_result {
	char name[MAX_SYM_LENGTH];
	__u64 start;
	__u64 end;
	char desc[MAX_SYM_ADDR_LENGTH];
	__u64 pc;
	struct sym_result *next;
};

struct sym_result *sym_parse_exact(__u64 pc);
struct sym_result *sym_parse(__u64 pc);
int sym_search_pattern(char *name, char *result, bool partial);

static inline int sym_get_type(char *name)
{
	return sym_search_pattern(name, NULL, false);
}
