#include "errorhandle.h"
#include <errno.h>
#include <stdio.h>//cannot recognize exit(1)

void fatal(const char *fmt, ...){
	exit(1);//remain to add
}