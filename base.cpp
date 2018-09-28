#include "base.h"
#include "errorhandle.h"
#include "intf.h"
#include "scanops.h"
#include <iostream>
#include <errno.h>
#include <arpa/inet.h>	//inet_ntop
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <net/if.h>
#include <string.h>
#include <sys/stat.h>



extern ScanOps o;

/* Returns the UNIX/Windows errno-equivalent.  Note that the Windows
   call is socket/networking specific.  The windows error number
   returned is like WSAMSGSIZE, but nbase.h includes #defines to
   correlate many of the common UNIX errors with their closest Windows
   equivalents.  So you can use EMSGSIZE or EINTR. */
int socket_errno() {
#ifdef WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

/* We can't just use strerror to get socket errors on Windows because it has
   its own set of error codes: WSACONNRESET not ECONNRESET for example. This
   function will do the right thing on Windows. Call it like
     socket_strerror(socket_errno())
*/
char *socket_strerror(int errnum) {
#ifdef WIN32
    static char buffer[128];

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_MAX_WIDTH_MASK,
        0, errnum, 0, buffer, sizeof(buffer), NULL);

    return buffer;
#else
    return strerror(errnum);
#endif
}


/* data for our random state */
struct nrand_handle {
  u8    i, j, s[256], *tmp;
  int   tmplen;
};
typedef struct nrand_handle nrand_h;



/* This function is an easier version of inet_ntop because you don't
   need to pass a dest buffer.  Instead, it returns a static buffer that
   you can use until the function is called again (by the same or another
   thread in the process).  If there is a weird error (like sslen being
   too short) then NULL will be returned. */
const char *inet_ntop_ez(const struct sockaddr_storage *ss, size_t sslen) {

  const struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  static char str[INET6_ADDRSTRLEN];
#if HAVE_IPV6
  const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
#endif

  str[0] = '\0';

  if (sin->sin_family == AF_INET) {
    if (sslen < sizeof(struct sockaddr_in))
      return NULL;
    return inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str));
  }
#if HAVE_IPV6
  else if(sin->sin_family == AF_INET6) {
    if (sslen < sizeof(struct sockaddr_in6))
      return NULL;
    return inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str));
  }
#endif
  //Some laptops report the ip and address family of disabled wifi cards as null
  //so yes, we will hit this sometimes.
  return NULL;
}


static void nrand_addrandom(nrand_h *rand, u8 *buf, int len) {
  int i;
  u8 si;

  /* Mix entropy in buf with s[]...
   *
   * This is the ARC4 key-schedule.  It is rather poor and doesn't mix
   * the key in very well.  This causes a bias at the start of the stream.
   * To eliminate most of this bias, the first N bytes of the stream should
   * be dropped.
   */
  rand->i--;
  for (i = 0; i < 256; i++) {
    rand->i = (rand->i + 1);
    si = rand->s[rand->i];
    rand->j = (rand->j + si + buf[i % len]);
    rand->s[rand->i] = rand->s[rand->j];
    rand->s[rand->j] = si;
  }
  rand->j = rand->i;
}

static u8 nrand_getbyte(nrand_h *r) {
  u8 si, sj;

  /* This is the core of ARC4 and provides the pseudo-randomness */
  r->i = (r->i + 1);
  si = r->s[r->i];
  r->j = (r->j + si);
  sj = r->s[r->j];
  r->s[r->i] = sj; /* The start of the the swap */
  r->s[r->j] = si; /* The other half of the swap */
  return (r->s[(si + sj) & 0xff]);
}

int nrand_get(nrand_h *r, void *buf, size_t len) {
  u8 *p;
  size_t i;

  /* Hand out however many bytes were asked for */
  for (p = (u8 *)buf, i = 0; i < len; i++) {//the same problem
    p[i] = nrand_getbyte(r);
  }
  return (0);
}

void nrand_init(nrand_h *r) {
  u8 seed[256]; /* Starts out with "random" stack data */
  int i;

  /* Gather seed entropy with best the OS has to offer */
  //ignore some codes that only function in WIN32
  struct timeval *tv = (struct timeval *)seed;
  int *pid = (int *)(seed + sizeof(*tv));
  int fd;

  gettimeofday(tv, NULL); /* fill lowest seed[] with time */
  *pid = getpid();        /* fill next lowest seed[] with pid */

  /* Try to fill the rest of the state with OS provided entropy */
  if ((fd = open("/dev/urandom", O_RDONLY)) != -1 ||
      (fd = open("/dev/arandom", O_RDONLY)) != -1) {
    ssize_t n;
    do {
      errno = 0;
      n = read(fd, seed + sizeof(*tv) + sizeof(*pid),
               sizeof(seed) - sizeof(*tv) - sizeof(*pid));
    } while (n < 0 && errno == EINTR);
    close(fd);
  }


  /* Fill up our handle with starter values */
  for (i = 0; i < 256; i++) { r->s[i] = i; };
  r->i = r->j = 0;

  nrand_addrandom(r, seed, 128); /* lower half of seed data for entropy */
  nrand_addrandom(r, seed + 128, 128); /* Now use upper half */
  r->tmp = NULL;
  r->tmplen = 0;

  /* This stream will start biased.  Get rid of 1K of the stream */
  nrand_get(r, seed, 256); nrand_get(r, seed, 256);
  nrand_get(r, seed, 256); nrand_get(r, seed, 256);
}

int get_random_bytes(void *buf, int numbytes) {
  static nrand_h state;
  static int state_init = 0;

  /* Initialize if we need to */
  if (!state_init) {
    nrand_init(&state);
    state_init = 1;
  }

  /* Now fill our buffer */
  nrand_get(&state, buf, numbytes);

  return 0;
}

int get_random_int() {
  int i;
  get_random_bytes(&i, sizeof(int));
  return i;
}

unsigned int get_random_uint() {
  unsigned int i;
  get_random_bytes(&i, sizeof(unsigned int));
  return i;
}

u64 get_random_u64() {
  u64 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}


u32 get_random_u32() {
  u32 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u16 get_random_u16() {
  u16 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u8 get_random_u8() {
  u8 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

unsigned short get_random_ushort() {
  unsigned short s;
  get_random_bytes(&s, sizeof(unsigned short));
  return s;
}

/* This function is magic ;-)
 *
 * Sometimes Nmap wants to generate IPs that look random
 * but don't have any duplicates.  The strong RC4 generator
 * can't be used for this purpose because it can generate duplicates
 * if you get enough IPs (birthday paradox).
 *
 * This routine exploits the fact that a LCG won't repeat for the
 * entire duration of its period.  An LCG has some pretty bad
 * properties though so this routine does extra work to try to
 * tweak the LCG output so that is has very good statistics but
 * doesn't repeat.  The tweak used was mostly made up on the spot
 * but is generally based on good ideas and has been moderately
 * tested.  See links and reasoning below.
 */
u32 get_random_unique_u32() {
  static u32 state, tweak1, tweak2, tweak3;
  static int state_init = 0;
  u32 output;

  /* Initialize if we need to */
  if (!state_init) {
    get_random_bytes(&state, sizeof(state));
    get_random_bytes(&tweak1, sizeof(tweak1));
    get_random_bytes(&tweak2, sizeof(tweak2));
    get_random_bytes(&tweak3, sizeof(tweak3));

    state_init = 1;
  }

  /* What is this math crap?
   *
   * The whole idea behind this generator is that an LCG can be constructed
   * with a period of exactly 2^32.  As long as the LCG is fed back onto
   * itself the period will be 2^32.  The tweak after the LCG is just
   * a good permutation in GF(2^32).
   *
   * To accomplish the tweak the notion of rounds and round keys from
   * block ciphers has been borrowed.  The only special aspect of this
   * block cipher is that the first round short-circuits the LCG.
   *
   * This block cipher uses three rounds.  Each round is as follows:
   *
   * 1) Affine transform in GF(2^32)
   * 2) Rotate left by round constant
   * 3) XOR with round key
   *
   * For round one the affine transform is used as an LCG.
   */

  /* Reasoning:
   *
   * Affine transforms were chosen both to make a LCG and also
   * to try to introduce non-linearity.
   *
   * The rotate up each round was borrowed from SHA-1 and was introduced
   * to help obscure the obvious short cycles when you truncate an LCG with
   * a power-of-two period like the one used.
   *
   * The XOR with the round key was borrowed from several different
   * published functions (but see Xorshift)
   * and provides a different sequence for the full LCG.
   * There are 3 32 bit round keys.  This generator can
   * generate 2^96 different sequences of period 2^32.
   *
   * This generator was tested with Dieharder.  It did not fail any test.
   */

  /* See:
   *
   * http://en.wikipedia.org/wiki/Galois_field
   * http://en.wikipedia.org/wiki/Affine_cipher
   * http://en.wikipedia.org/wiki/Linear_congruential_generator
   * http://en.wikipedia.org/wiki/Xorshift
   * http://en.wikipedia.org/wiki/Sha-1
   *
   * http://seclists.org/nmap-dev/2009/q3/0695.html
   */


  /* First off, we need to evolve the state with our LCG
   * We'll use the LCG from Numerical Recipes (m=2^32,
   * a=1664525, c=1013904223).  All by itself this generator
   * pretty bad.  We're going to try to fix that without causing
   * duplicates.
   */
  state = (((state * 1664525) & 0xFFFFFFFF) + 1013904223) & 0xFFFFFFFF;

  output = state;

  /* With a normal LCG, we would just output the state.
   * In this case, though, we are going to try to destroy the
   * linear correlation between IPs by approximating a random permutation
   * in GF(2^32) (collision-free)
   */

  /* Then rotate and XOR */
  output = ((output << 7) | (output >> (32 - 7)));
  output = output ^ tweak1; /* This is the round key */

  /* End round 1, start round 2 */

  /* Then put it through an affine transform (glibc constants) */
  output = (((output * 1103515245) & 0xFFFFFFFF) + 12345) & 0xFFFFFFFF;

  /* Then rotate and XOR some more */
  output = ((output << 15) | (output >> (32 - 15)));
  output = output ^ tweak2;

  /* End round 2, start round 3 */

  /* Then put it through another affine transform (Quick C/C++ constants) */
  output = (((output * 214013) & 0xFFFFFFFF) + 2531011) & 0xFFFFFFFF;

  /* Then rotate and XOR some more */
  output = ((output << 5) | (output >> (32 - 5)));
  output = output ^ tweak3;

  return output;
}

void *safe_malloc(size_t size) {
  void *mymem;

  if ((int)size < 0)            /* Catch caller errors */
    fatal("Tried to malloc negative amount of memory!!!");
  mymem = malloc(size);
  if (mymem == NULL)
    fatal("Malloc Failed! Probably out of space.");
  return mymem;
}


void *safe_realloc(void *ptr, size_t size) {
  void *mymem;

  if ((int)size < 0)            /* Catch caller errors */
    fatal("Tried to realloc negative amount of memory!!!");
  mymem = realloc(ptr, size);
  if (mymem == NULL)
    fatal("Realloc Failed! Probably out of space.");
  return mymem;
}

/* Zero-initializing version of safe_malloc */
void *safe_zalloc(size_t size) {
  void *mymem;

  if ((int)size < 0)
    fatal("Tried to malloc negative amount of memory!!!");
  mymem = calloc(1, size);
  if (mymem == NULL)
    fatal("Malloc Failed! Probably out of space.");
  return mymem;
}


int Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  if (dest[n - 1] == '\0')
    return 0;
  dest[n - 1] = '\0';
  return -1;
}

/* This is like strtol or atoi, but it allows digits only. No whitespace, sign,
   or radix prefix. */
long parse_long(const char *s, char **tail)
{
    if (!isdigit((int) (unsigned char) *s)) {
        *tail = (char *) s;
        return 0;
    }

    return strtol(s, (char **) tail, 10);
}


/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst,const char *src, size_t siz)
{
  register char *d = dst;
  register const char *s = src;
  register size_t n = siz;

  /* Copy as many bytes as will fit */
  if (n != 0 && --n != 0) {
    do {
      if ((*d++ = *s++) == 0)
        break;
    } while (--n != 0);
  }

  /* Not enough room in dst, add NUL and traverse rest of src */
  if (n == 0) {
    if (siz != 0)
      *d = '\0';    /* NUL-terminate dst */
    while (*s++)
      ;
  }

  return(s - src - 1);  /* count does not include NUL */
}

int Vsnprintf(char *s, size_t n, const char *fmt, va_list ap) {
  int ret;

  ret = vsnprintf(s, n, fmt, ap);

  if (ret < 0 || (unsigned)ret >= n)
    s[n - 1] = '\0';

  return ret;
}

int Snprintf(char *s, size_t n, const char *fmt, ...) {
  va_list ap;
  int ret;

  va_start(ap, fmt);
  ret = Vsnprintf(s, n, fmt, ap);
  va_end(ap);

  return ret;
}

/* Make a new allocated null-terminated string from the bytes [start, end). */
char *mkstr(const char *start, const char *end) {
  char *s;

  assert(end >= start);
  s = (char *)safe_malloc(end - start + 1);
  memcpy(s, start, end - start);
  s[end - start] = '\0';

  return s;
}

void addrset_init(struct addrset *set)
{
    set->head = NULL;
}

/* vsprintf into a dynamically allocated buffer, similar to asprintf in
   Glibc. Return the length of the buffer or -1 on error. */
int alloc_vsprintf(char **strp, const char *fmt, va_list va) {
  va_list va_tmp;
  char *s;
  int size = 32;
  int n;

  s = NULL;
  size = 32;
  for (;;) {
    s = (char *)safe_realloc(s, size);

#ifdef WIN32
    va_tmp = va;
#else
    va_copy(va_tmp, va);
#endif
    n = vsnprintf(s, size, fmt, va_tmp);

    if (n >= size)
      size = n + 1;
    else if (n < 0)
      size = size * 2;
    else
      break;
  }
  *strp = s;

  return n;
}

/* Compares two sockaddr_storage structures with a return value like strcmp.
   First the address families are compared, then the addresses if the families
   are equal. The structures must be real full-length sockaddr_storage
   structures, not something shorter like sockaddr_in. */
int sockaddr_storage_cmp(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b) {
  if (a->ss_family < b->ss_family)
    return -1;
  else if (a->ss_family > b->ss_family)
    return 1;
  if (a->ss_family == AF_INET) {
    struct sockaddr_in *sin_a = (struct sockaddr_in *) a;
    struct sockaddr_in *sin_b = (struct sockaddr_in *) b;
    if (sin_a->sin_addr.s_addr < sin_b->sin_addr.s_addr)
      return -1;
    else if (sin_a->sin_addr.s_addr > sin_b->sin_addr.s_addr)
      return 1;
    else
      return 0;
  } else if (a->ss_family == AF_INET6) {
    struct sockaddr_in6 *sin6_a = (struct sockaddr_in6 *) a;
    struct sockaddr_in6 *sin6_b = (struct sockaddr_in6 *) b;
    return memcmp(sin6_a->sin6_addr.s6_addr, sin6_b->sin6_addr.s6_addr,
                  sizeof(sin6_a->sin6_addr.s6_addr));
  } else {
    assert(0);
  }
  return 0; /* Not reached */
}

int sockaddr_storage_equal(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b) {
  return sockaddr_storage_cmp(a, b) == 0;
}

/* Break an IPv4 address into an array of octets. octets[0] contains the most
   significant octet and octets[3] the least significant. */
static void in_addr_to_octets(const struct in_addr *ia, uint8_t octets[4])
{
    u32 hbo = ntohl(ia->s_addr);

    octets[0] = (uint8_t) ((hbo & (0xFFU << 24)) >> 24);
    octets[1] = (uint8_t) ((hbo & (0xFFU << 16)) >> 16);
    octets[2] = (uint8_t) ((hbo & (0xFFU << 8)) >> 8);
    octets[3] = (uint8_t) (hbo & 0xFFU);
}

static int match_ipv4_bits(const octet_bitvector bits[4], const struct sockaddr *sa)
{
    uint8_t octets[4];

    if (sa->sa_family != AF_INET)
        return 0;

    in_addr_to_octets(&((const struct sockaddr_in *) sa)->sin_addr, octets);

    return BIT_IS_SET(bits[0], octets[0])
        && BIT_IS_SET(bits[1], octets[1])
        && BIT_IS_SET(bits[2], octets[2])
        && BIT_IS_SET(bits[3], octets[3]);
}

static int addrset_elem_match(const struct addrset_elem *elem, const struct sockaddr *sa)
{
    switch (elem->type) {
        case ADDRSET_TYPE_IPV4_BITVECTOR:
            return match_ipv4_bits(elem->u.ipv4.bits, sa);
#ifdef HAVE_IPV6
        case ADDRSET_TYPE_IPV6_NETMASK:
            return match_ipv6_netmask(&elem->u.ipv6.addr, &elem->u.ipv6.mask, sa);
#endif
    }//obviously we do not have ipv6

    return 0;
}


int addrset_contains(const struct addrset *set, const struct sockaddr *sa)
{
    struct addrset_elem *elem;

    for (elem = set->head; elem != NULL; elem = elem->next) {
        if (addrset_elem_match(elem, sa))
            return 1;
    }

    return 0;
}

/* Returns one if the file pathname given exists, is not a directory and
 * is readable by the executing process.  Returns two if it is readable
 * and is a directory.  Otherwise returns 0. */
int file_is_readable(const char *pathname) {
    char *pathname_buf = strdup(pathname);
    int status = 0;
    struct stat st;
/*
#ifdef WIN32
    // stat on windows only works for "dir_name" not for "dir_name/" or "dir_name\\"
    int pathname_len = strlen(pathname_buf);
    char last_char = pathname_buf[pathname_len - 1];

    if(    last_char == '/'
        || last_char == '\\')
        pathname_buf[pathname_len - 1] = '\0';

#endif
*/
    //we do not have WIN32
  if (stat(pathname_buf, &st) == -1)
    status = 0;
  else if (access(pathname_buf, R_OK) != -1)
    status = S_ISDIR(st.st_mode) ? 2 : 1;

  free(pathname_buf);
  return status;
}

static char *executable_path_argv0(const char *argv0) {
  if (argv0 == NULL)
    return NULL;
  /* We can get the path from argv[0] if it contains a directory separator.
     (Otherwise it was looked up in $PATH). */
  if (strchr(argv0, '/') != NULL)
    return strdup(argv0);
#if WIN32
  if (strchr(argv0, '\\') != NULL)
    return strdup(argv0);
#endif
  return NULL;
}

char *executable_path(const char *argv0) {
  char *path;

  path = NULL;
#if HAVE_PROC_SELF_EXE
  if (path == NULL)
    path = executable_path_proc_self_exe();
#endif
#if HAVE_MACH_O_DYLD_H
  if (path == NULL)
    path = executable_path_NSGetExecutablePath();
#endif
#if WIN32
  if (path == NULL)
    path = executable_path_GetModuleFileName();
#endif
  if (path == NULL)
    path = executable_path_argv0(argv0);

  return path;
}

/* Returns the position of the last directory separator (slash, also backslash
   on Win32) in a path. Returns -1 if none was found. */
static int find_last_path_separator(const char *path) {
#ifndef WIN32
  const char *PATH_SEPARATORS = "/";
#else
  const char *PATH_SEPARATORS = "\\/";
#endif
  const char *p;

  p = path + strlen(path) - 1;
  while (p >= path) {
    if (strchr(PATH_SEPARATORS, *p) != NULL)
      return (int)(p - path);
    p--;
  }

  return -1;
}

/* Returns the directory name part of a path (everything up to the last
   directory separator). If there is no separator, returns ".". If there is only
   one separator and it is the first character, returns "/". Returns NULL on
   error. The returned string must be freed. */
char *path_get_dirname(const char *path) {
  char *result;
  int i;

  i = find_last_path_separator(path);
  if (i == -1)
    return strdup(".");
  if (i == 0)
    return strdup("/");

  result = (char *)safe_malloc(i + 1);
  strncpy(result, path, i);
  result[i] = '\0';

  return result;
}

/* Use the SO_BINDTODEVICE sockopt to bind with a specific interface (Linux
   only). Pass NULL or an empty string to remove device binding. */
int socket_bindtodevice(int sd, const char *device) {
  char padded[sizeof(int)];
  size_t len;

  len = strlen(device) + 1;
  /* In Linux 2.6.20 and earlier, there is a bug in SO_BINDTODEVICE that causes
     EINVAL to be returned if the optlen < sizeof(int); this happens for example
     with the interface names "" and "lo". Pad the string with null characters
     so it is above this limit if necessary.
     http://article.gmane.org/gmane.linux.network/71887
     http://article.gmane.org/gmane.linux.network/72216 */
  if (len < sizeof(padded)) {
    /* We rely on strncpy padding with nulls here. */
    strncpy(padded, device, sizeof(padded));
    device = padded;
    len = sizeof(padded);
  }

#ifdef SO_BINDTODEVICE
  /* Linux-specific sockopt asking to use a specific interface. See socket(7). */
  if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, device, len) < 0)
    return 0;
#endif

  return 1;
}

int unblock_socket(int sd) {
#ifdef WIN32
  unsigned long one = 1;

  if (sd != 501) /* Hack related to WinIP Raw Socket support */
    ioctlsocket(sd, FIONBIO, &one);

  return 0;
#else
  int options;

  /* Unblock our socket to prevent recvfrom from blocking forever on certain
   * target ports. */
  options = fcntl(sd, F_GETFL);
  if (options == -1)
    return -1;

  return fcntl(sd, F_SETFL, O_NONBLOCK | options);
#endif /* WIN32 */
}


/*
 * CRC-32C (Castagnoli) Cyclic Redundancy Check.
 * Taken straight from Appendix C of RFC 4960 (SCTP), with the difference that
 * the remainder register (crc32) is initialized to 0xffffffffL rather than ~0L,
 * for correct operation on platforms where unsigned long is longer than 32
 * bits.
 */

/* Return the CRC-32C of the bytes buf[0..len-1] */
unsigned long nbase_crc32c(unsigned char *buf, int len)
{
  int i;
  unsigned long crc32 = 0xffffffffL;
  unsigned long result;
  unsigned char byte0, byte1, byte2, byte3;

  for (i = 0; i < len; i++) {
    CRC32C(crc32, buf[i]);
  }

  result = ~crc32;

  /*  result now holds the negated polynomial remainder;
   *  since the table and algorithm is "reflected" [williams95].
   *  That is, result has the same value as if we mapped the message
   *  to a polynomial, computed the host-bit-order polynomial
   *  remainder, performed final negation, then did an end-for-end
   *  bit-reversal.
   *  Note that a 32-bit bit-reversal is identical to four inplace
   *  8-bit reversals followed by an end-for-end byteswap.
   *  In other words, the bytes of each bit are in the right order,
   *  but the bytes have been byteswapped.  So we now do an explicit
   *  byteswap.  On a little-endian machine, this byteswap and
   *  the final ntohl cancel out and could be elided.
   */

  byte0 =  result        & 0xff;
  byte1 = (result >>  8) & 0xff;
  byte2 = (result >> 16) & 0xff;
  byte3 = (result >> 24) & 0xff;
  crc32 = ((byte0 << 24) | (byte1 << 16) | (byte2 <<  8) | byte3);
  return crc32;
}

/*
 * Adler32 Checksum Calculation.
 * Taken straight from RFC 2960 (SCTP).
 */

#define ADLER32_BASE 65521 /* largest prime smaller than 65536 */

/*
 * Update a running Adler-32 checksum with the bytes buf[0..len-1]
 * and return the updated checksum.  The Adler-32 checksum should
 * be initialized to 1.
 */
static unsigned long update_adler32(unsigned long adler,
                                    unsigned char *buf, int len)
{
  unsigned long s1 = adler & 0xffff;
  unsigned long s2 = (adler >> 16) & 0xffff;
  int n;

  for (n = 0; n < len; n++) {
    s1 = (s1 + buf[n]) % ADLER32_BASE;
    s2 = (s2 + s1)     % ADLER32_BASE;
  }
  return (s2 << 16) + s1;
}

/* Return the Adler32 of the bytes buf[0..len-1] */
unsigned long nbase_adler32(unsigned char *buf, int len)
{
  return update_adler32(1L, buf, len);
}

// #ifndef HAVE_USLEEP
// void usleep(unsigned long usec) {
// #ifdef HAVE_NANOSLEEP
// struct timespec ts;
// ts.tv_sec = usec / 1000000;
// ts.tv_nsec = (usec % 1000000) * 1000;
// nanosleep(&ts, NULL);
// #else /* Windows style */
//  Sleep( usec / 1000 );
// #endif /* HAVE_NANOSLEEP */
// }
// #endif

/* This function returns a string containing the hexdump of the supplied
 * buffer. It uses current locale to determine if a character is printable or
 * not. It prints 73char+\n wide lines like these:

0000   e8 60 65 86 d7 86 6d 30  35 97 54 87 ff 67 05 9e  .`e...m05.T..g..
0010   07 5a 98 c0 ea ad 50 d2  62 4f 7b ff e1 34 f8 fc  .Z....P.bO{..4..
0020   c4 84 0a 6a 39 ad 3c 10  63 b2 22 c4 24 40 f4 b1  ...j9.<.c.".$@..

 * The lines look basically like Wireshark's hex dump.
 * WARNING: This function returns a pointer to a DYNAMICALLY allocated buffer
 * that the caller is supposed to free().
 * */
char *hexdump(const u8 *cp, u32 length){
  static char asciify[257];          /* Stores character table           */
  int asc_init=0;                    /* Flag to generate table only once */
  u32 i=0, hex=0, asc=0;             /* Array indexes                    */
  u32 line_count=0;                  /* For byte count at line start     */
  char *current_line=NULL;           /* Current line to write            */
  char *buffer=NULL;                 /* Dynamic buffer we return         */
  #define LINE_LEN 74                /* Length of printed line           */
  char line2print[LINE_LEN];         /* Stores current line              */
  char printbyte[16];                /* For byte conversion              */
  int bytes2alloc;                   /* For buffer                       */
  memset(line2print, ' ', LINE_LEN); /* We fill the line with spaces     */

  /* On the first run, generate a list of nice printable characters
   * (according to current locale) */
  if( asc_init==0){
      asc_init=1;
      for(i=0; i<256; i++){
        if( isalnum(i) || isdigit(i) || ispunct(i) ){ asciify[i]=i; }
        else{ asciify[i]='.'; }
      }
  }
  /* Allocate enough space to print the hex dump */
  bytes2alloc=(length%16==0)? (1 + LINE_LEN * (length/16)) : (1 + LINE_LEN * (1+(length/16))) ;
  buffer=(char *)safe_zalloc(bytes2alloc);
  current_line=buffer;
#define HEX_START 7
#define ASC_START 57
/* This is how or line looks like.
0000   00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  .`e...m05.T..g..[\n]
01234567890123456789012345678901234567890123456789012345678901234567890123
0         1         2         3         4         5         6         7
       ^                                                 ^               ^
       |                                                 |               |
    HEX_START                                        ASC_START        Newline
*/
  i=0;
  while( i < length ){
    memset(line2print, ' ', LINE_LEN); /* Fill line with spaces */
    snprintf(line2print, sizeof(line2print), "%04x", (16*line_count++) % 0xFFFF); /* Add line No.*/
    line2print[4]=' '; /* Replace the '\0' inserted by snprintf() with a space */
    hex=HEX_START;  asc=ASC_START;
    do { /* Print 16 bytes in both hex and ascii */
        if (i%16 == 8) hex++; /* Insert space every 8 bytes */
        snprintf(printbyte, sizeof(printbyte), "%02x", cp[i]);/* First print the hex number */
        line2print[hex++]=printbyte[0];
        line2print[hex++]=printbyte[1];
        line2print[hex++]=' ';
        line2print[asc++]=asciify[ cp[i] ]; /* Then print its ASCII equivalent */
        i++;
    } while (i < length && i%16 != 0);
    /* Copy line to output buffer */
    line2print[LINE_LEN-1]='\n';
    memcpy(current_line, line2print, LINE_LEN);
    current_line += LINE_LEN;
  }
  buffer[bytes2alloc-1]='\0';
  return buffer;
} /* End of hexdump() */


#undef ADLER32_BASE


/*
 * CRC32 Cyclic Redundancy Check
 *
 * From: http://www.ietf.org/rfc/rfc1952.txt
 *
 * Copyright (c) 1996 L. Peter Deutsch
 *
 * Permission is granted to copy and distribute this document for any
 * purpose and without charge, including translations into other
 * languages and incorporation into compilations, provided that the
 * copyright notice and this notice are preserved, and that any
 * substantive changes or deletions from the original are clearly
 * marked.
 *
 */

/* Table of CRCs of all 8-bit messages. */
static unsigned long crc_table[256];

/* Flag: has the table been computed? Initially false. */
static int crc_table_computed = 0;

/* Make the table for a fast CRC. */
static void make_crc_table(void)
{
  unsigned long c;
  int n, k;

  for (n = 0; n < 256; n++) {
    c = (unsigned long) n;
    for (k = 0; k < 8; k++) {
      if (c & 1) {
        c = 0xedb88320L ^ (c >> 1);
      } else {
        c = c >> 1;
      }
    }
    crc_table[n] = c;
  }
  crc_table_computed = 1;
}

/*
   Update a running crc with the bytes buf[0..len-1] and return
 the updated crc. The crc should be initialized to zero. Pre- and
 post-conditioning (one's complement) is performed within this
 function so it shouldn't be done by the caller. Usage example:

   unsigned long crc = 0L;

   while (read_buffer(buffer, length) != EOF) {
     crc = update_crc(crc, buffer, length);
   }
   if (crc != original_crc) error();
*/
static unsigned long update_crc(unsigned long crc,
                unsigned char *buf, int len)
{
  unsigned long c = crc ^ 0xffffffffL;
  int n;

  if (!crc_table_computed)
    make_crc_table();
  for (n = 0; n < len; n++) {
    c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
  }
  return c ^ 0xffffffffL;
}

/* Return the CRC of the bytes buf[0..len-1]. */
unsigned long nbase_crc32(unsigned char *buf, int len)
{
  return update_crc(0L, buf, len);
}

void addrset_free(struct addrset *set)
{
    struct addrset_elem *elem, *next;

    for (elem = set->head; elem != NULL; elem = next) {
        next = elem->next;
        free(elem);
    }
}
