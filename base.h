#ifndef MY_BASE_H
#define MY_BASE_H

#include <limits.h>//CHAR_BIT

/* Integer types */
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

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

#endif
