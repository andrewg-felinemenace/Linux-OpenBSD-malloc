#include <string.h>
#include <sys/mman.h>
#include <pthread.h>

#ifndef MADV_FREE
#define MADV_FREE MADV_DONTNEED
#endif

#define PGSHIFT 12

#define issetugid() ((geteuid() != getuid()) || (getegid() != getgid()))


void __attribute__((visibility("hidden"))) arc4random_addrandom(u_char *dat, int datlen);
u_int32_t __attribute__((visibility("hidden"))) arc4random(void);
void __attribute__((visibility("hidden"))) arc4random_buf(void *_buf, size_t n);

u_int32_t __attribute__((visibility("hidden"))) arc4random_uniform(u_int32_t upper_bound);

void __attribute__((visibility("hidden"))) arc4random_stir(void);

