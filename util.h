#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

void die(const char *msg);
void *xmalloc(size_t n);
void secure_bzero(void *p, size_t n);

uint16_t load_u16_be(const uint8_t *p);
uint32_t load_u32_be(const uint8_t *p);
uint64_t load_u64_be(const uint8_t *p);
void store_u16_be(uint8_t *p, uint16_t v);
void store_u32_be(uint8_t *p, uint32_t v);
void store_u64_be(uint8_t *p, uint64_t v);

ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, const void *buf, size_t n);
int ct_memcmp(const void *a, const void *b, size_t n);

#endif
