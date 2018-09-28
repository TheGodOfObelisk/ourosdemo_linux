#ifndef MY_UTIL_H
#define MY_UTIL_H
#include "base.h"
#include <assert.h>
// #include <stdio.h>

/* Arithmatic difference modulo 2^32 */
#ifndef MOD_DIFF
#define MOD_DIFF(a,b) ((u32) (MIN((u32)(a) - (u32 ) (b), (u32 )(b) - (u32) (a))))
#endif

void shortfry(unsigned short *arr, int num_elem);

/* Return num if it is between min and max.  Otherwise return min or max
   (whichever is closest to num). */
template<class T> T box(T bmin, T bmax, T bnum) {
  assert(bmin <= bmax);
  if (bnum >= bmax)
    return bmax;
  if (bnum <= bmin)
    return bmin;
  return bnum;
}

void genfry(unsigned char *arr, int elem_sz, int num_elem);

char *cstring_unescape(char *str, unsigned int *len);

char *chomp(char *string);

void nmap_hexdump(unsigned char *cp, unsigned int length);

void bintohexstr(char *buf, int buflen, char *src, int srclen);

int wildtest(char *wild, char *test);

#endif