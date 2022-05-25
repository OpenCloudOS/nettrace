#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "parse_sym.h"

#define SWAP(a, b) { typeof(a) _tmp = (b); (b) = (a); (a) = _tmp; }

struct sym_result *result_list;
struct loc_result *loc_list;

static void add_sym_cache(struct sym_result *result)
{
	if (!result_list) {
		result_list = result;
		result->next = NULL;
		return;
	}
	result->next = result_list;
	result_list = result;
}

static struct sym_result *lookup_sym_cache(__u64 pc)
{
	struct sym_result *head = result_list, *sym = NULL;
	while (head) {
		if (head->start >= pc && head->end < pc) {
			if (head->pc == pc)
				return head;
			sym = head;
		}
		head = head->next;
	}
	if (!sym)
		return NULL;
	head = malloc(sizeof(*head));
	if (!head)
		return NULL;
	memcpy(head, sym, sizeof(*head));
	head->pc = pc;
	sprintf(head->desc, "%s+0x%x", head->name, pc - head->start);
	add_sym_cache(head);
	return head;
}

static struct sym_result *lookup_sym_proc(__u64 pc)
{
	char _cname[MAX_SYM_LENGTH], _pname[MAX_SYM_LENGTH],
	     *pname = _pname, *cname = _cname, *tmp;
	struct sym_result *result;
	__u64 cpc, ppc = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		goto err;

	result = malloc(sizeof(*result));
	if (!result)
		goto err;

	while (true) {
		if (fscanf(f, "%llx %*s %s [ %*[^]] ]", &cpc, cname) < 0)
			break;

		if (pc < ppc || pc >= cpc) {
			SWAP(cname, pname);
			ppc = cpc;
			continue;
		}

		strcpy(result->name, pname);
		result->start = ppc;
		result->end = cpc;
		result->pc = pc;
		sprintf(result->desc, "%s+0x%x", result->name,
			pc - result->start);
		add_sym_cache(result);
		goto ok;
	}

out_close:
	fclose(f);
out_free:
	free(result);
err:
	return NULL;

ok:
	fclose(f);
	return result;
}

struct sym_result *parse_sym(__u64 pc)
{
	if (!pc)
		return NULL;
	return lookup_sym_cache(pc) ?: lookup_sym_proc(pc);
}
