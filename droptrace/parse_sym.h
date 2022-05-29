#include <asm-generic/int-ll64.h>

#define MAX_SYM_LENGTH		128
#define MAX_SYM_ADDR_LENGTH	(MAX_SYM_LENGTH + 8)

struct sym_result {
	char name[MAX_SYM_LENGTH];
	__u64 start;
	__u64 end;
	char desc[MAX_SYM_ADDR_LENGTH];
	__u64 pc;
	struct sym_result *next;
};

struct sym_result *parse_sym(__u64 pc);