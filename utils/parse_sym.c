// SPDX-License-Identifier: MulanPSL-2.0

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "parse_sym.h"
#include "sys_utils.h"

static char *proc_syms = NULL;
struct sym_result *result_list;
struct loc_result *loc_list;

static int sym_init_data()
{
	size_t size = 1024 * 1024 * 4; // begin with 4M
	char *cur, *tmp;
	size_t count;
	FILE *f;

	if (proc_syms)
		return 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		pr_err("/proc/kallsyms is not founded!\n");
		exit(-1);
	}

	proc_syms = malloc(size + 1);
	cur = proc_syms;
	while (true) {
		size_t offset;

		count = fread(cur, sizeof(char), size + proc_syms - cur, f);
		cur += count;
		if (feof(f))
			break;

		offset = cur - proc_syms;
		size <<= 1;
		tmp = realloc(proc_syms, size + 1);
		cur = tmp + offset;
		proc_syms = tmp;
	}
	*cur = '\0';
	fclose(f);

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
	char cname[MAX_SYM_LENGTH], pname[MAX_SYM_LENGTH] = {}, *line;
	bool has_prev = false;
	__u64 cpc, ppc = 0;

	if (sym_init_data())
		return NULL;

	line = proc_syms;
	while (*line) {
		struct sym_result *result;
		char tname, *line_end;
		int count;

		line_end = strchr(line, '\n');
		if (line_end)
			*line_end = '\0';
		count = sscanf(line, "%llx %c %255s", &cpc, &tname, cname);
		if (line_end)
			*line_end = '\n';
		if (count != 3 || (tname != 'T' && tname != 't'))
			goto next_line;

		if (!has_prev) {
			strcpy(pname, cname);
			ppc = cpc;
			has_prev = true;
			goto next_line;
		}

		if (exact) {
			if (ppc != pc)
				goto update_prev;
		} else {
			if (pc < ppc || pc >= cpc)
				goto update_prev;
		}

		result = malloc(sizeof(*result));
		if (!result)
			return NULL;

		strcpy(result->name, pname);
		result->start = ppc;
		result->end = cpc;
		result->pc = pc;
		sprintf(result->desc, "%s+0x%llx", result->name,
			pc - result->start);
		sym_add_cache(result);
		return result;

update_prev:
		strcpy(pname, cname);
		ppc = cpc;
next_line:
		if (!line_end)
			break;
		line = line_end + 1;
	}

	return NULL;
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

int sym_search_pattern(const char *name, char *result, bool partial)
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
