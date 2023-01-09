// SPDX-License-Identifier: MulanPSL-2.0

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "parse_sym.h"
#include "sys_utils.h"

#define SWAP(a, b) { typeof(a) _tmp = (b); (b) = (a); (a) = _tmp; }

static char *proc_syms = NULL;
struct sym_result *result_list;
struct loc_result *loc_list;

static int sym_init_data()
{
	size_t size = 1024 * 1024 * 4; // begin with 4M
	size_t left = size;
	char *cur, *tmp;
	int count;
	FILE *f;

	if (proc_syms)
		return 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		pr_err("/proc/kallsyms is not founded!\n");
		exit(-1);
	}

	proc_syms = malloc(size);
	cur = proc_syms;
	while (true) {
		count = fread(cur, sizeof(char), size + proc_syms - cur,
			      f);
		if (feof(f))
			break;

		size *= 2;
		tmp = realloc(proc_syms, size);
		cur = tmp + (cur - proc_syms) + count;
		proc_syms = tmp;
	}

	return 0;
}

static void sym_add_cache(struct sym_result *result)
{
	if (!result_list) {
		result_list = result;
		result->next = NULL;
		return;
	}
	result->next = result_list;
	result_list = result;
}

static struct sym_result *sym_lookup_cache(__u64 pc, bool exact)
{
	struct sym_result *head = result_list, *sym = NULL;
	while (head) {
		if (!exact) {
			if (pc >= head->start && pc < head->end) {
				if (head->pc == pc)
					return head;
				sym = head;
				break;
			}
		} else {
			if (head->start == pc)
				return head;
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
	sprintf(head->desc, "%s+0x%llx", head->name, pc - head->start);
	sym_add_cache(head);
	return head;
}

static struct sym_result *sym_lookup_proc(__u64 pc, bool exact)
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

		if (exact) {
			if (ppc != pc) {
				SWAP(cname, pname);
				ppc = cpc;
				continue;
			}
		} else {
			if (pc < ppc || pc >= cpc) {
				SWAP(cname, pname);
				ppc = cpc;
				continue;
			}
		}

		strcpy(result->name, pname);
		result->start = ppc;
		result->end = cpc;
		result->pc = pc;
		sprintf(result->desc, "%s+0x%llx", result->name,
			pc - result->start);
		sym_add_cache(result);
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

struct sym_result *sym_parse(__u64 pc)
{
	if (!pc)
		return NULL;
	return sym_lookup_cache(pc, false) ?: sym_lookup_proc(pc, false);
}

struct sym_result *sym_parse_exact(__u64 pc)
{
	if (!pc)
		return NULL;
	return sym_lookup_cache(pc, true) ?: sym_lookup_proc(pc, true);
}

int sym_search_pattern(char *name, char *result, bool partial)
{
	char func[128], module[128], search[128], *target;
	int count;

	sym_init_data();

	sprintf(search, " %s", name);
	target = proc_syms;
	while (true) {
		target = strstr(target, search);
		if (!target)
			break;

		count = sscanf(target, " %s [%[^]]]", func, module);
		target++;

		if (count <= 0)
			continue;

		if (partial && strncmp(func, name, strlen(name)) == 0)
				goto found;
		if (!partial && strcmp(func, name) == 0)
				goto found;
	}

	return SYM_NOT_EXIST;
found:
	if (result)
		strcpy(result, func);

	return count == 2 ? SYM_MODULE : SYM_KERNEL;
}
