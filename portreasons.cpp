#include "portreasons.h"

/* Set the ip_addr union to the AF_INET or AF_INET6 value stored in *ss as
   appropriate. Returns 0 on success or -1 if the address family of *ss is not
   known. */
int port_reason::set_ip_addr(const struct sockaddr_storage *ss) {
  if (ss->ss_family == AF_INET) {
    this->ip_addr.in = *(struct sockaddr_in *) ss;
    return 0;
  } else if (ss->ss_family == AF_INET6) {
    this->ip_addr.in6 = *(struct sockaddr_in6 *) ss;
    return 0;
  } else {
    return -1;
  }
}
