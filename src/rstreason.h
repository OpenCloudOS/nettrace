#ifndef _H_TCP_RESET_REASON
#define _H_TCP_RESET_REASON

#include <stdbool.h>

char *get_reset_reason(int index);
bool reset_reason_support();
const char *get_tcp_state_str(unsigned char state);

#endif
