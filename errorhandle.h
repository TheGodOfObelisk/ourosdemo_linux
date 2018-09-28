//borrow from nmap's nmap_error.h
//aim to implement some error handing functions
#ifndef ERROR_HANDLE_H
#define ERROR_HANDLE_H

#include "base.h"

#include <stdlib.h>

#include <stdarg.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
//we use g++
void fatal(const char *fmt, ...)
		__attribute__((format (printf, 1, 2)));
void error(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));

void pfatal(const char *err, ...)
     __attribute__ ((format (printf, 1, 2)));
void gh_perror(const char *err, ...)
     __attribute__ ((format (printf, 1, 2)));

#ifdef __cplusplus
}
#endif

#endif//ERROR_HANDLE_H