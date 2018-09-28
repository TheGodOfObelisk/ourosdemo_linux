#ifndef SERVICES_H
#define SERVICES_H
#include "scan_lists.h"
#include "base.h"
#include <netdb.h>

/* just flags to indicate whether a particular port number should get tcp
 * scanned, udp scanned, or both
 */
#define SCAN_TCP_PORT	(1 << 0)
#define SCAN_UDP_PORT	(1 << 1)
#define SCAN_SCTP_PORT	(1 << 2)
#define SCAN_PROTOCOLS	(1 << 3)

void gettoppts(double level, char *portlist, struct scan_lists * ports, char *exclude_list = NULL);

int addportsfromservmask(char *mask, u8 *porttbl, int range_type);

struct servent *nmap_getservbyport(int port, const char *proto);

void free_services();
#endif