#include "route.h"
#include "base.h"
#include "addr.h"
#include "ip.h"
#include "ip6.h"
//#include <memory.h>
//#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

//#include <pcap.h>
#include <net/route.h>
//#include <asm/types.h>
//#include <net/if.h>
//#include <netinet/in.h>
//#include <linux/netlink.h>
#include <linux/rtnetlink.h>
//#include <sys/types.h>
//#include <sys/ioctl.h>
//#include <sys/socket.h>
#include <stdio.h>

#define PROC_ROUTE_FILE		"/proc/net/route"
#define PROC_IPV6_ROUTE_FILE	"/proc/net/ipv6_route"


route_t *
route_open(void)
{
	struct sockaddr_nl snl;
	route_t *r;
if ((r =(route_t *) calloc(1, sizeof(*r))) != NULL) { //convertion from void * to (route_t *)
		r->fd = r->nlfd = -1;
		
		if ((r->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			return (route_close(r));
		
		if ((r->nlfd = socket(AF_NETLINK, SOCK_RAW,
			 NETLINK_ROUTE)) < 0)
			return (route_close(r));
		
		memset(&snl, 0, sizeof(snl));
		snl.nl_family = AF_NETLINK;
		
		if (bind(r->nlfd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
			return (route_close(r));
	}
	return (r);
}

int
route_loop(route_t *r, route_handler callback, void *arg)
{
    FILE *fp;
	struct route_entry entry;
	char buf[BUFSIZ];
	char ifbuf[16];
	int ret = 0;

	if ((fp = fopen(PROC_ROUTE_FILE, "r")) != NULL) {
		int i, iflags, refcnt, use, metric, mss, win, irtt;
		uint32_t mask;
		
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			i = sscanf(buf, "%15s %X %X %X %d %d %d %X %d %d %d\n",
			    ifbuf, &entry.route_dst.addr_ip,
			    &entry.route_gw.addr_ip, &iflags, &refcnt, &use,
			    &metric, &mask, &mss, &win, &irtt);
			
			if (i < 11 || !(iflags & RTF_UP))
				continue;
		
			strlcpy(entry.intf_name, ifbuf, sizeof(entry.intf_name));

			entry.route_dst.addr_type = entry.route_gw.addr_type =
			    ADDR_TYPE_IP;
		
			if (addr_mtob(&mask, IP_ADDR_LEN,
				&entry.route_dst.addr_bits) < 0)
				continue;
			
			entry.route_gw.addr_bits = IP_ADDR_BITS;
			entry.metric = metric;
			
			if ((ret = callback(&entry, arg)) != 0)
				break;
		}
		fclose(fp);
	}
	if (ret == 0 && (fp = fopen(PROC_IPV6_ROUTE_FILE, "r")) != NULL) {
		char s[33], d[8][5], n[8][5];
		int i, iflags, metric;
		u_int slen, dlen;
		
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			i = sscanf(buf, "%04s%04s%04s%04s%04s%04s%04s%04s %02x "
			    "%32s %02x %04s%04s%04s%04s%04s%04s%04s%04s "
			    "%x %*x %*x %x %15s",
			    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
			    &dlen, s, &slen,
			    n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7],
			    &metric, &iflags, ifbuf);
			
			if (i < 21 || !(iflags & RTF_UP))
				continue;

			strlcpy(entry.intf_name, ifbuf, sizeof(entry.intf_name));

			snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
			    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
			    dlen);
			addr_aton(buf, &entry.route_dst);
			snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
			    n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7],
			    IP6_ADDR_BITS);
			addr_aton(buf, &entry.route_gw);
			entry.metric = metric;
			
			if ((ret = callback(&entry, arg)) != 0)
				break;
		}
		fclose(fp);
	}
	return (ret);
}



route_t *
route_close(route_t *r)
{
	if (r != NULL) {
		if (r->fd >= 0)
			close(r->fd);
		if (r->nlfd >= 0)
			close(r->nlfd);
		free(r);
	}
	return (NULL);
}