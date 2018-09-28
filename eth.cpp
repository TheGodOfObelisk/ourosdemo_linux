#include "eth.h"
#include "base.h"
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
int
eth_pton(const char *p, eth_addr_t *eth)
{
	char *ep;
	long l;
	int i;
	
	for (i = 0; i < ETH_ADDR_LEN; i++) {
		l = strtol(p, &ep, 16);
		if (ep == p || l < 0 || l > 0xff ||
		    (i < ETH_ADDR_LEN - 1 && *ep != ':'))
			break;
		eth->data[i] = (u_char)l;
		p = ep + 1;
	}
	return ((i == ETH_ADDR_LEN && *ep == '\0') ? 0 : -1);

}

eth_t *
eth_open(const char *device)
{
	eth_t *e;
	int n;
	
	if ((e = (eth_t *)calloc(1, sizeof(*e))) != NULL) {//my type conversion
		if ((e->fd = socket(PF_PACKET, SOCK_RAW,
			 htons(ETH_P_ALL))) < 0)
			return (eth_close(e));
#ifdef SO_BROADCAST
		n = 1;
		if (setsockopt(e->fd, SOL_SOCKET, SO_BROADCAST, &n,
			sizeof(n)) < 0)
			return (eth_close(e));
#endif
		strlcpy(e->ifr.ifr_name, device, sizeof(e->ifr.ifr_name));
		
		if (ioctl(e->fd, SIOCGIFINDEX, &e->ifr) < 0)
			return (eth_close(e));
		
		e->sll.sll_family = AF_PACKET;
		e->sll.sll_ifindex = e->ifr.ifr_ifindex;
	}
	return (e);
}

eth_t *
eth_close(eth_t *e)
{
	if (e != NULL) {
		if (e->fd >= 0)
			close(e->fd);
		free(e);
	}
	return (NULL);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
	struct eth_hdr *eth = (struct eth_hdr *)buf;
	
	e->sll.sll_protocol = eth->eth_type;

	return (sendto(e->fd, buf, len, 0, (struct sockaddr *)&e->sll,
	    sizeof(e->sll)));
}
