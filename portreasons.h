#ifndef PORTREASONS_H
#define PORTREASONS_H

#include <netinet/in.h>

typedef unsigned short reason_t;

/* stored inside a Port Object and describes
 * why a port is in a specific state */
typedef struct port_reason {
        reason_t reason_id;
        union {
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
                struct sockaddr sockaddr;
        } ip_addr;
        unsigned short ttl;

        int set_ip_addr(const struct sockaddr_storage *ss);
} state_reason_t;


#endif