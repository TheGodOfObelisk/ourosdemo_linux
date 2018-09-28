
#ifndef DNET_IP6_H
#define DNET_IP6_H
#include "addr.h"

#define IP6_ADDR_LEN	16
#define IP6_ADDR_BITS	12


char	*ip6_ntop(const ip6_addr_t *ip6, char *dst, size_t size);

int	 ip6_pton(const char *src, ip6_addr_t *dst);
#endif /* DNET_IP6_H */
