#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys_utils.h>

#include "rstreason.h"

#define REASON_MAX_COUNT 256
#define REASON_MAX_LEN 32

static char reset_reasons[REASON_MAX_COUNT][REASON_MAX_LEN] = {};
static int reset_reason_max;
static bool reset_reason_inited = false;
static const char *tcp_state_str[] = {
    "UNKNOWN",           // 0
    "TCP_ESTABLISHED",   // 1
    "TCP_SYN_SENT",      // 2
    "TCP_SYN_RECV",      // 3
    "TCP_FIN_WAIT1",     // 4
    "TCP_FIN_WAIT2",     // 5
    "TCP_TIME_WAIT",     // 6
    "TCP_CLOSE",         // 7
    "TCP_CLOSE_WAIT",    // 8
    "TCP_LAST_ACK",      // 9
    "TCP_LISTEN",        // 10
    "TCP_CLOSING",       // 11
    "TCP_NEW_SYN_RECV",  // 12
    "TCP_MAX_STATES"     // 13
};

/* check if rst reason is supported */
bool reset_reason_support() 
{
	return simple_exec("cat /sys/kernel/debug/tracing/events/tcp/"
        "tcp_send_reset/format 2>/dev/null | "
        "grep NOT_SPECIFIED") == 0;
}

static int parse_reason_enum() 
{
    char name[REASON_MAX_LEN];
    int index = 0;
    FILE *f;
    int symbolics_found = 1;

    f = fopen("/sys/kernel/debug/tracing/events/tcp/tcp_send_reset/format", "r");

    if (!f || !fsearch(f, "__print_symbolic")) {
        if (f)
            fclose(f);
        return -1;
    }

    while (true) {
        if (symbolics_found == 1 &&
            fsearch(f, "__print_symbolic")) {
            symbolics_found++;
        }
        
        if (symbolics_found == 2) {
            if (!fsearch(f, "{") ||
                fscanf(f, "%d, \"%31[A-Z_0-9]", &index, name) != 2)
                break;
            pr_debug("reset_reason[%d] = %s\n", index, name);
            strcpy(reset_reasons[index], name);
        } else if (feof(f)) {
            fclose(f);
            return -1;
        }
    }
    reset_reason_max = index;
    reset_reason_inited = true;

    fclose(f);
    return 0;
}

char *get_reset_reason(int index)
{
	if (!reset_reason_inited && parse_reason_enum())
		return NULL;
	if (index <= 0 || index > reset_reason_max)
		return NULL;

	return reset_reasons[index];
}

const char *get_tcp_state_str(unsigned char state) {
    if (state < 0 || state >= sizeof(tcp_state_str) / sizeof(tcp_state_str[0])) {
        return "UNKNOWN";
    }
    return tcp_state_str[state];
}