#ifndef _H_SKB_DROP_REASON
#define _H_SKB_DROP_REASON

#include <stdbool.h>

char *get_drop_reason(int index);
bool drop_reason_support();

#endif
