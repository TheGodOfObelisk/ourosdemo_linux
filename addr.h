#ifndef MY_ADDR_H
#define MY_ADDR_H
//it is also borrowed from libdnet
#include "base.h"
#include "eth.h"
#include <stdio.h>//extremely important
#define ETH_ADDR_LEN  6
#define IP6_ADDR_LEN  16

#define ADDR_TYPE_NONE    0 /* No address set */
#define ADDR_TYPE_ETH   1 /* Ethernet */
#define ADDR_TYPE_IP    2 /* Internet Protocol v4 */
#define ADDR_TYPE_IP6   3 /* Internet Protocol v6 */


typedef uint32_t  ip_addr_t;

typedef struct ip6_addr {
  uint8_t         data[IP6_ADDR_LEN];
} ip6_addr_t;

struct addr {
  uint16_t    addr_type;
  uint16_t    addr_bits;
  union {
    eth_addr_t  __eth;
    ip_addr_t __ip;
    ip6_addr_t  __ip6;
    
    uint8_t   __data8[16];
    uint16_t  __data16[8];
    uint32_t  __data32[4];
  } __addr_u;
};

#define addr_eth	__addr_u.__eth
#define addr_ip		__addr_u.__ip
#define addr_ip6	__addr_u.__ip6
#define addr_data8	__addr_u.__data8
#define addr_data16	__addr_u.__data16
#define addr_data32	__addr_u.__data32


int  addr_pton(const char *src, struct addr *dst);
#define  addr_aton  addr_pton
int	 addr_ston(const struct sockaddr *sa, struct addr *a);
int	 addr_ntos(const struct addr *a, struct sockaddr *sa);
int	 addr_stob(const struct sockaddr *sa, uint16_t *bits);
int  addr_btom(uint16_t bits, void *mask, size_t size);
int   addr_mtob(const void *mask, size_t size, uint16_t *bits);
#endif