#if defined(__TARGET_ARCH_x86)
#include "./progs/vmlinux_x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "./progs/vmlinux_arm64.h"
#elif defined(__TARGET_ARCH_loongarch)
#include "./progs/vmlinux_loongarch64.h"
#endif
