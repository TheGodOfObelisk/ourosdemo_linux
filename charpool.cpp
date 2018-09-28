#include <stddef.h>

#include "base.h"

/* Character pool memory allocation */
#include "charpool.h"
#include "errorhandle.h"

static char *charpool[16];
static int currentcharpool;
static int currentcharpoolsz;
static char *nextchar;

/* Allocated blocks are allocated to multiples of ALIGN_ON. This is the
   definition used by the malloc in Glibc 2.7, which says that it "suffices for
   nearly all current machines and C compilers." */
#define ALIGN_ON (2 * sizeof(size_t))

static int cp_init(void) {
  static int charpool_initialized = 0;
  if (charpool_initialized) return 0;

  /* Create our char pool */
  currentcharpool = 0;
  currentcharpoolsz = 16384;
  nextchar = charpool[0] = (char *) safe_malloc(currentcharpoolsz);
  charpool_initialized = 1;
  return 0;
}

void cp_free(void) {
  int ccp;
  for(ccp=0; ccp <= currentcharpool; ccp++)
    if(charpool[ccp]){
      free(charpool[ccp]);
      charpool[ccp] = NULL;
  }
  currentcharpool = 0;
}

static inline void cp_grow(void) {
  /* Doh!  We've got to make room */
  if (++currentcharpool > 15) {
    fatal("Character Pool is out of buckets!");
  }
  currentcharpoolsz <<= 1;

  nextchar = charpool[currentcharpool] = (char *)
    safe_malloc(currentcharpoolsz);
}

void *cp_alloc(int sz) {
  char *p;
  int modulus;

  cp_init();

  if ((modulus = sz % ALIGN_ON))
    sz += ALIGN_ON - modulus;

  if ((nextchar - charpool[currentcharpool]) + sz <= currentcharpoolsz) {
    p = nextchar;
    nextchar += sz;
    return p;
  }
  /* Doh!  We've got to make room */
  cp_grow();

 return cp_alloc(sz);

}

char *cp_strdup(const char *src) {
const char *p;
char *q;
/* end points to the first illegal char */
char *end;
int modulus;

 cp_init();

 end = charpool[currentcharpool] + currentcharpoolsz;
 q = nextchar;
 p = src;
 while((nextchar < end) && *p) {
   *nextchar++ = *p++;
 }

 if (nextchar < end) {
   /* Goody, we have space */
   *nextchar++ = '\0';
   if ((modulus = (nextchar - q) % ALIGN_ON))
     nextchar += ALIGN_ON - modulus;
   return q;
 }

 /* Doh!  We ran out -- need to allocate more */
 cp_grow();

 return cp_strdup(src);
}
