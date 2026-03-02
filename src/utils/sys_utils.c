// SPDX-License-Identifier: MulanPSL-2.0

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include "sys_utils.h"

static int __hz = -1;
static char *proc_syms;
static struct sym_result *result_list;
int log_level = 0;

#define SYM_BULK_HASH_BITS	10
#define SYM_BULK_HASH_SIZE	(1U << SYM_BULK_HASH_BITS)

struct sym_bulk_req {
	const char *name;
	int index;
	struct sym_bulk_req *next;
};

#define SWAP(a, b) { typeof(a) _tmp = (b); (b) = (a); (a) = _tmp; }

static unsigned int sym_bulk_hash_name(const char *name)
{
	unsigned long hash = 5381;
	unsigned char c;

	while ((c = (unsigned char)*name++))
		hash = ((hash << 5) + hash) + c;

	return (unsigned int)hash & (SYM_BULK_HASH_SIZE - 1);
}

static unsigned int sym_bulk_hash_slice(const char *name, size_t len)
{
	unsigned long hash = 5381;
	size_t i;

	for (i = 0; i < len; i++)
		hash = ((hash << 5) + hash) + (unsigned char)name[i];

	return (unsigned int)hash & (SYM_BULK_HASH_SIZE - 1);
}

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
	char func[128], module_name[128], search[128], *target;
	int count;

	sym_init_data();

	sprintf(search, " %s", name);
	target = proc_syms;
	while (true) {
		target = strstr(target, search);
		if (!target)
			break;

		count = sscanf(target, " %s [%[^]]]", func, module_name);
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

int sym_get_types_bulk(const char **names, int nr, int *types)
{
	struct sym_bulk_req *table[SYM_BULK_HASH_SIZE] = {};
	const char *p, *line_end;
	int unresolved = 0;
	int i;

	if (!names || !types || nr <= 0)
		return -EINVAL;

	sym_init_data();
	/* generate a hash table for the symbol names. */
	for (i = 0; i < nr; i++) {
		struct sym_bulk_req *req;
		unsigned int idx;

		types[i] = SYM_NOT_EXIST;
		if (!names[i] || !names[i][0])
			continue;

		req = calloc(1, sizeof(*req));
		if (!req)
			continue;

		req->name = names[i];
		req->index = i;
		idx = sym_bulk_hash_name(names[i]);
		req->next = table[idx];
		table[idx] = req;
		unresolved++;
	}

	p = proc_syms;
	while (*p && unresolved > 0) {
		const char *sp1, *sp2, *name_start, *name_end, *meta;
		struct sym_bulk_req *req;
		size_t name_len;
		unsigned int idx;
		int type = SYM_KERNEL;

		line_end = strchr(p, '\n');
		if (!line_end)
			line_end = p + strlen(p);
		if (line_end <= p)
			goto next_line;

		sp1 = memchr(p, ' ', line_end - p);
		if (!sp1 || sp1 + 2 >= line_end)
			goto next_line;
		sp2 = memchr(sp1 + 2, ' ', line_end - (sp1 + 2));
		if (!sp2 || sp2 + 1 >= line_end)
			goto next_line;

		name_start = sp2 + 1;
		name_end = name_start;
		while (name_end < line_end && *name_end != ' ')
			name_end++;
		if (name_end <= name_start)
			goto next_line;
		name_len = name_end - name_start;

		meta = name_end;
		while (meta < line_end && *meta == ' ')
			meta++;
		if (meta < line_end && *meta == '[')
			type = SYM_MODULE;

		idx = sym_bulk_hash_slice(name_start, name_len);
		/* check if the symbol exists in the hash table */
		for (req = table[idx]; req; req = req->next) {
			if (types[req->index] != SYM_NOT_EXIST)
				continue;
			if (strlen(req->name) != name_len)
				continue;
			if (strncmp(req->name, name_start, name_len))
				continue;
			types[req->index] = type;
			unresolved--;
		}

next_line:
		p = line_end;
		if (*p == '\n')
			p++;
	}

	for (i = 0; i < SYM_BULK_HASH_SIZE; i++) {
		struct sym_bulk_req *req = table[i];
		while (req) {
			struct sym_bulk_req *next = req->next;
			free(req);
			req = next;
		}
	}

	return 0;
}

int exec(char *cmd, char *output)
{
	FILE *f = popen(cmd, "r");
	char buf[128];
	int status;

	if (output)
		output[0] = '\0';

	while (fgets(buf, sizeof(buf) - 1, f) != NULL) {
		if (!output)
			continue;
		strcat(output + strlen(output), buf);
	}

	status = pclose(f);
	pr_debug("command: %s, status:%d\n", cmd, WEXITSTATUS(status));
	return WEXITSTATUS(status);
}

int execf(char *output, char *fmt, ...)
{
	static char cmd[1024];
	va_list valist;

	va_start(valist, fmt);
	vsprintf(cmd, fmt, valist);
	va_end(valist);

	return exec(cmd, output);
}

int liberate_l()
{
	struct rlimit lim = {RLIM_INFINITY, RLIM_INFINITY};
	return setrlimit(RLIMIT_MEMLOCK, &lim);
}

bool fsearch(FILE *f, char *target)
{
	char tmp[128];

	while (fscanf(f, "%s", tmp) == 1) {
		if (strstr(tmp, target))
			return true;
	}
	return false;
}

int kernel_version()
{
	int major, minor, patch;
	struct utsname buf;

	uname(&buf);
	sscanf(buf.release, "%d.%d.%d", &major, &minor, &patch);

	return kv_to_num(major, minor, patch);
}

char *kernel_version_str()
{
	static char version[16];
	int major, minor, patch;
	struct utsname buf;

	uname(&buf);
	sscanf(buf.release, "%d.%d.%d", &major, &minor, &patch);
	sprintf(version, "%d.%d.%d", major, minor, patch);

	return version;
}

bool debugfs_mounted()
{
	return simple_exec("mount | grep debugfs") == 0;
}

char *get_tracing_path()
{
	if (file_exist("/sys/kernel/debug/tracing/trace"))
		return "/sys/kernel/debug/tracing/";
	return "/sys/kernel/tracing/";
}

int kernel_get_config(char *name, char *output)
{
	char tmp[128] = {};
	int err;

	if (file_exist("/proc/config.gz"))
		err = execf(tmp, "zcat /proc/config.gz | grep 'CONFIG_%s=' 2>&1",
			    name);
	else
		err = execf(tmp, "grep 'CONFIG_%s=' /boot/config-$(uname -r)"
			    " 2>&1", name);

	if (!output || err)
		return err;

	sscanf(tmp, "%*[^=]=%s", output);
	return err;
}

bool kernel_has_config(char *name)
{
	char type[32] = {};
	return kernel_get_config(name, type) == 0 && type[0] == 'y';
}

int kernel_hz()
{
	char hz[32] = {};
	int err;

	if (__hz > 0)
		return __hz;

	err = kernel_get_config("HZ", hz);
	if (err)
		return -ENOTSUP;

	__hz = atoi(hz);
	return __hz;
}

u32 file_inode(char *path)
{
	char tmp1[128], tmp2[128];
	struct stat file_stat;
	char *__path = path;
	u32 inode;

	if (!file_exist(path))
		return 0;

again:
	if (sscanf(__path, "%*[^:]:[%u]", &inode) == 1)
		return inode;

	if (stat(__path, &file_stat) == -1)
		return 0;

	if (S_ISLNK(file_stat.st_mode)) {
		if (readlink(path, tmp1, sizeof(tmp1)) == -1)
			return 0;
		memcpy(tmp2, tmp1, sizeof(tmp1));
		__path = tmp2;
		goto again;
	}

	return file_stat.st_ino;
}
