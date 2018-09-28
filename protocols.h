#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include "base.h"
#include <netdb.h>

#define PROTOCOL_TABLE_SIZE 256
#define MAX_IPPROTOSTRLEN 4
struct protocol_list {
  struct protoent *protoent;
  struct protocol_list *next;
};


#define IPPROTO2STR(p)		\
  ((p)==IPPROTO_TCP ? "tcp" :	\
   (p)==IPPROTO_UDP ? "udp" :	\
   (p)==IPPROTO_SCTP ? "sctp" :	\
   "n/a")

int addprotocolsfromservmask(char *mask, u8 *porttbl);

struct protoent *nmap_getprotbynum(int num);

#endif