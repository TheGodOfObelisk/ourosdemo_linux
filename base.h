#ifndef MY_BASE_H
#define MY_BASE_H
//combine nbase.h, nbase_ipv6.h, nmap.h, intf.h
#include <limits.h>//CHAR_BIT
#include <netinet/in.h>
#include <sys/time.h>
#include <net/if.h>
#include <stdarg.h>//va_list
/* Integer types */
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#if defined(__GNUC__)
#define NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER)
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif
#define FP_RESULT_WRAP_LINE_LEN 74
#define NMAP_VERSION "7.70"

#define NMAP_PLATFORM "i686-pc-windows-windows"
#define MAX_DECOYS 128 /* How many decoys are allowed? */

/* Number of hosts we pre-ping and then scan.  We do a lot more if
   randomize_hosts is set.  Every one you add to this leads to ~1K of
   extra always-resident memory in nmap */
#define PING_GROUP_SZ 4096

/* We wait at least 100 ms for a response by default - while that
   seems aggressive, waiting too long can cause us to fail to detect
   drops until many probes later on extremely low-latency
   networks (such as localhost scans).  */
#ifndef MIN_RTT_TIMEOUT
#define MIN_RTT_TIMEOUT 100
#endif

#ifndef MAX_RTT_TIMEOUT
#define MAX_RTT_TIMEOUT 10000 /* Never allow more than 10 secs for packet round
                                 trip */
#endif

#define INITIAL_RTT_TIMEOUT 1000 /* Allow 1 second initially for packet responses */

#ifndef MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS 10    /* 11 probes to port at maximum */
#endif

/* Default maximum send delay between probes to the same host */
#ifndef MAX_TCP_SCAN_DELAY
#define MAX_TCP_SCAN_DELAY 1000
#endif

#ifndef MAX_UDP_SCAN_DELAY
#define MAX_UDP_SCAN_DELAY 1000
#endif

#ifndef MAX_SCTP_SCAN_DELAY
#define MAX_SCTP_SCAN_DELAY 1000
#endif

#define PINGTYPE_UNKNOWN 0
#define PINGTYPE_NONE 1
#define PINGTYPE_ICMP_PING 2
#define PINGTYPE_ICMP_MASK 4
#define PINGTYPE_ICMP_TS 8
#define PINGTYPE_TCP  16
#define PINGTYPE_TCP_USE_ACK 32
#define PINGTYPE_TCP_USE_SYN 64
/* # define PINGTYPE_RAWTCP 128 used to be here, but was never used. */
#define PINGTYPE_CONNECTTCP 256
#define PINGTYPE_UDP  512
#define PINGTYPE_ARP 1024
#define PINGTYPE_PROTO 2048
#define PINGTYPE_SCTP_INIT 4096


/* Mathematical MIN/MAX/ABS (absolute value) macros */
#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif
#ifndef ABS
#define ABS(x) (((x) >= 0)?(x):-(x))
#endif

//borrowed from nmap.h, and it is used in HOST DISCOVERY
#define HOST_UNKNOWN 0
#define HOST_UP 1
#define HOST_DOWN 2

#define INITIAL_RTT_TIMEOUT 1000 /* Allow 1 second initially for packet responses */
#define INITIAL_ARP_RTT_TIMEOUT 200 /* The initial timeout for ARP is lower */

/* Empirically determined optimum combinations of different numbers of probes:
     -PE
     -PE -PA80
     -PE -PA80 -PS443
     -PE -PA80 -PS443 -PP
     -PE -PA80 -PS443 -PP -PU40125
   We use the four-probe combination. */
#define DEFAULT_IPV4_PING_TYPES (PINGTYPE_ICMP_PING|PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_TCP_USE_SYN|PINGTYPE_ICMP_TS)
#define DEFAULT_IPV6_PING_TYPES (PINGTYPE_ICMP_PING|PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_TCP_USE_SYN)
#define DEFAULT_PING_ACK_PORT_SPEC "80"
#define DEFAULT_PING_SYN_PORT_SPEC "443"
/* For nonroot. */
#define DEFAULT_PING_CONNECT_PORT_SPEC "80,443"

//nmap define them both in TargetGroup.cc and nbase_addrset.cc
#define BITVECTOR_BITS (sizeof(bitvector_t) * CHAR_BIT)
#define BIT_SET(v, n) ((v)[(n) / BITVECTOR_BITS] |= 1UL << ((n) % BITVECTOR_BITS))
#define BIT_IS_SET(v, n) (((v)[(n) / BITVECTOR_BITS] & 1UL << ((n) % BITVECTOR_BITS)) != 0)

/* Timeval subtraction in microseconds */
#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)
/* Timeval subtract in milliseconds */
#define TIMEVAL_MSEC_SUBTRACT(a,b) ((((a).tv_sec - (b).tv_sec) * 1000) + ((a).tv_usec - (b).tv_usec) / 1000)
/* Timeval subtract in seconds; truncate towards zero */
#define TIMEVAL_SEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec < (b).tv_usec) ? - 1 : 0))
/* Timeval subtract in fractional seconds; convert to float */
#define TIMEVAL_FSEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec - (b).tv_usec)/1000000.0))

/* assign one timeval to another timeval plus some msecs: a = b + msecs */
#define TIMEVAL_MSEC_ADD(a, b, msecs) { (a).tv_sec = (b).tv_sec + ((msecs) / 1000); (a).tv_usec = (b).tv_usec + ((msecs) % 1000) * 1000; (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }
#define TIMEVAL_ADD(a, b, usecs) { (a).tv_sec = (b).tv_sec + ((usecs) / 1000000); (a).tv_usec = (b).tv_usec + ((usecs) % 1000000); (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }

/* Find our if one timeval is before or after another, avoiding the integer
   overflow that can result when doing a TIMEVAL_SUBTRACT on two widely spaced
   timevals. */
#define TIMEVAL_BEFORE(a, b) (((a).tv_sec < (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec < (b).tv_usec))
#define TIMEVAL_AFTER(a, b) (((a).tv_sec > (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec > (b).tv_usec))

/* Convert a timeval to floating point seconds */
#define TIMEVAL_SECS(a) ((double) (a).tv_sec + (double) (a).tv_usec / 1000000)


struct probespec_tcpdata {
  u16 dport;
  u8 flags;
};

struct probespec_udpdata {
  u16 dport;
};

struct probespec_sctpdata {
  u16 dport;
  u8 chunktype;
};

struct probespec_icmpdata {
  u8 type;
  u8 code;
};

struct probespec_icmpv6data {
  u8 type;
  u8 code;
};

#define PS_NONE 0
#define PS_TCP 1
#define PS_UDP 2
#define PS_PROTO 3
#define PS_ICMP 4
#define PS_ARP 5
#define PS_CONNECTTCP 6
#define PS_SCTP 7
#define PS_ICMPV6 8
#define PS_ND 9

/* The size of this structure is critical, since there can be tens of
   thousands of them stored together ... */
typedef struct probespec {
  /* To save space, I changed this from private enum (took 4 bytes) to
     u8 that uses #defines above */
  u8 type;
  u8 proto; /* If not PS_ARP -- Protocol number ... eg IPPROTO_TCP, etc. */
  union {
    struct probespec_tcpdata tcp; /* If type is PS_TCP or PS_CONNECTTCP. */
    struct probespec_udpdata udp; /* PS_UDP */
    struct probespec_sctpdata sctp; /* PS_SCTP */
    struct probespec_icmpdata icmp; /* PS_ICMP */
    struct probespec_icmpv6data icmpv6; /* PS_ICMPV6 */
    /* Nothing needed for PS_ARP, since src mac and target IP are
       avail from target structure anyway */
  } pd;
} probespec;//it is so sad that I borrow it from scan_engine.h
//scan_engine.h needs target.h while target.h needs scan_engine.h

/* TCP Options for TCP SYN probes: MSS 1460 */
#define TCP_SYN_PROBE_OPTIONS "\x02\x04\x05\xb4"
#define TCP_SYN_PROBE_OPTIONS_LEN (sizeof(TCP_SYN_PROBE_OPTIONS)-1)
//it is used in scan_engine_raw.cpp

/* The version number of updates retrieved by the nmap-update
   program. It can be different (but should always be the same or
   earlier) than NMAP_VERSION. */
//the nmap version that I plagiarize is 7.70
#define NMAP_UPDATE_CHANNEL "7.70"
#define NMAPDATADIR "c:\\nmap" /* FIXME: I really need to make this dynamic */
  /* Some routines for obtaining simple (not secure on systems that
     lack /dev/random and friends' "random" numbers */
int get_random_bytes(void *buf, int numbytes);
int get_random_int();
unsigned short get_random_ushort();
unsigned int get_random_uint();
u64 get_random_u64();
u32 get_random_u32();
u16 get_random_u16();
u8 get_random_u8();
u32 get_random_unique_u32();



enum addrset_elem_type {//borrowed from nbase_addrset.h
    ADDRSET_TYPE_IPV4_BITVECTOR,
/*
#ifdef HAVE_IPV6
    ADDRSET_TYPE_IPV6_NETMASK,
#endif
*/
//suppose we do not have ipv6
};


/* We use bit vectors to represent what values are allowed in an IPv4 octet.
   Each vector is built up of an array of bitvector_t (any convenient integer
   type). */
typedef unsigned long bitvector_t;
/* A 256-element bit vector, representing legal values for one octet. */
typedef bitvector_t octet_bitvector[(256 - 1) / (sizeof(unsigned long) * CHAR_BIT) + 1];

/* A chain of tests for set inclusion. If one test is passed, the address is in
   the set. */
struct addrset_elem {
    enum addrset_elem_type type;
    union {
        struct {
            /* A bit vector for each address octet. */
            octet_bitvector bits[4];
        } ipv4;
/*
#ifdef HAVE_IPV6
        struct {
            struct in6_addr addr;
            struct in6_addr mask;
        } ipv6;
#endif
*/
//suppose that we do not have ipv6
    } u;
    struct addrset_elem *next;
};


/* A set of addresses. Used to match against allow/deny lists. */
struct addrset {
    /* Linked list of struct addset_elem. */
    struct addrset_elem *head;
};

/* This function is an easier version of inet_ntop because you don't
   need to pass a dest buffer.  Instead, it returns a static buffer that
   you can use until the function is called again (by the same or another
   thread in the process).  If there is a weird error (like sslen being
   too short) then NULL will be returned. */
const char *inet_ntop_ez(const struct sockaddr_storage *ss, size_t sslen);

/* Zero-initializing version of safe_malloc */
void *safe_zalloc(size_t size);
/* A few simple wrappers for the most common memory allocation routines which will exit() if the
   allocation fails, so you don't always have to check -- see nbase_memalloc.c */
void *safe_malloc(size_t size);
void *safe_realloc(void *ptr, size_t size);

int alloc_vsprintf(char **strp, const char *fmt, va_list va)
     __attribute__ ((format (printf, 2, 0)));

/* parse_long is like strtol or atoi, but it allows digits only.
   No whitespace, sign, or radix prefix. */
long parse_long(const char *s, char **tail);

/* diy strlcpy in that g++ doesn't support strlcpy */
size_t strlcpy(char *dst,const char *src, size_t siz);
/* Strncpy is like strcpy() except it ALWAYS zero-terminates, even if
   it must truncate */
int Strncpy(char *dest, const char *src, size_t n);

int Vsnprintf(char *, size_t, const char *, va_list)
     __attribute__ ((format (printf, 3, 0)));
int Snprintf(char *, size_t, const char *, ...)
     __attribute__ ((format (printf, 3, 4)));

char *mkstr(const char *start, const char *end);

  /* Returns the UNIX/Windows errno-equivalent.  Note that the Windows
     call is socket/networking specific.  Also, WINDOWS TENDS TO RESET
     THE ERROR, so it will return success the next time.  So SAVE THE
     RESULTS and re-use them, don't keep calling socket_errno().  The
     windows error number returned is like WSAMSGSIZE, but nbase.h
     includes #defines to correlate many of the common UNIX errors
     with their closest Windows equivalents.  So you can use EMSGSIZE
     or EINTR. */
int socket_errno();

/* We can't just use strerror to get socket errors on Windows because it has
   its own set of error codes: WSACONNRESET not ECONNRESET for example. This
   function will do the right thing on Windows. Call it like
     socket_strerror(socket_errno())
*/
char *socket_strerror(int errnum);

//In original nbase.h, there is a previous keyword -- extern
void addrset_init(struct addrset *set);
int addrset_contains(const struct addrset *set, const struct sockaddr *sa);//extern?

/* Compares two sockaddr_storage structures with a return value like strcmp.
   First the address families are compared, then the addresses if the families
   are equal. The structures must be real full-length sockaddr_storage
   structures, not something shorter like sockaddr_in. */
int sockaddr_storage_cmp(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b);

/* Does sockaddr_storage_cmp(a, b) == 0 for you. */
int sockaddr_storage_equal(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b);

//it should have been in nmap.h
int nmap_fetchfile(char *filename_returned, int bufferlen, const char *file);

/* Returns one if the file pathname given exists, is not a directory and
 * is readable by the executing process.  Returns two if it is readable
 * and is a directory.  Otherwise returns 0. */
int file_is_readable(const char *pathname);

char *executable_path(const char *argv0);

/* Portable, incompatible replacements for dirname and basename. */
char *path_get_dirname(const char *path);


static inline int checked_fd_isset(int fd, fd_set *fds) {
#ifndef WIN32
  if (fd >= FD_SETSIZE) {
    fprintf(stderr, "Attempt to FD_ISSET fd %d, which is not less than "
                    "FD_SETSIZE (%d). Try using a lower parallelism.",
                    fd, FD_SETSIZE);
    abort();
  }
#endif
  return FD_ISSET(fd, fds);
}

static inline void checked_fd_clr(int fd, fd_set *fds) {
#ifndef WIN32
  if (fd >= FD_SETSIZE) {
    fprintf(stderr, "Attempt to FD_CLR fd %d, which is not less than "
                    "FD_SETSIZE (%d). Try using a lower parallelism.",
                    fd, FD_SETSIZE);
    abort();
  }
#endif
  FD_CLR(fd, fds);
}

static inline void checked_fd_set(int fd, fd_set *fds) {
#ifndef WIN32
  if (fd >= FD_SETSIZE) {
    fprintf(stderr, "Attempt to FD_SET fd %d, which is not less than "
                    "FD_SETSIZE (%d). Try using a lower parallelism.",
                    fd, FD_SETSIZE);
    abort();
  }
#endif
  FD_SET(fd, fds);
}

int socket_bindtodevice(int sd, const char *device);

int unblock_socket(int sd);
#define _STR(X) #X
#define STR(X)  _STR(X)
#define DEFAULT_TCP_PROBE_PORT 80 /* The ports TCP ping probes go to if
                                     unspecified by user -- uber hackers
                                     change this to 113 */
#define DEFAULT_TCP_PROBE_PORT_SPEC STR(DEFAULT_TCP_PROBE_PORT)
#define DEFAULT_UDP_PROBE_PORT 40125 /* The port UDP ping probes go to
                                          if unspecified by user */
#define DEFAULT_UDP_PROBE_PORT_SPEC STR(DEFAULT_UDP_PROBE_PORT)
#define DEFAULT_SCTP_PROBE_PORT 80 /* The port SCTP probes go to
                                      if unspecified by
                                      user */
#define DEFAULT_SCTP_PROBE_PORT_SPEC STR(DEFAULT_SCTP_PROBE_PORT)
#define DEFAULT_PROTO_PROBE_PORT_SPEC "1,2,4" /* The IPProto ping probes to use
                                                 if unspecified by user */

/* CRC32C Cyclic Redundancy Check (Castagnoli) */
unsigned long nbase_crc32c(unsigned char *buf, int len);
/* Adler32 Checksum */
unsigned long nbase_adler32(unsigned char *buf, int len);

#define CRC32C_POLY 0x1EDC6F41
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

static unsigned long crc_c[256] = {
0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,
};

/* The usleep() function is important as well */
// #ifndef HAVE_USLEEP
// #if defined( HAVE_NANOSLEEP) || defined(WIN32)
// void usleep(unsigned long usec);
// #endif
// #endif


char *hexdump(const u8 *cp, u32 length);

#ifndef recvfrom6_t
#  define recvfrom6_t int
#endif

#define ARPHRD_ETHER  1 /* ethernet hardware format */


/* CRC32 Cyclic Redundancy Check */
unsigned long nbase_crc32(unsigned char *buf, int len);

void addrset_free(struct addrset *set);

#endif
