#ifndef MY_CHAR_POOL_H
#define MY_CHAR_POOL_H

void *cp_alloc(int sz);
char *cp_strdup(const char *src);

void cp_free(void);

#endif