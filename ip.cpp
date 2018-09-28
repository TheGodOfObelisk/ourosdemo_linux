#include "ip.h"
#include "addr.h"
#include <stdlib.h>
int
ip_pton(const char *p, ip_addr_t *ip)
{
	u_char *data = (u_char *)ip;
	char *ep;
	long l;
	int i;

	for (i = 0; i < IP_ADDR_LEN; i++) {
		l = strtol(p, &ep, 10);
		if (ep == p || l < 0 || l > 0xff ||
		    (i < IP_ADDR_LEN - 1 && *ep != '.'))
			break;
		data[i] = (u_char)l;
		p = ep + 1;
	}
	return ((i == IP_ADDR_LEN && *ep == '\0') ? 0 : -1);
}

int
ip_cksum_add(const void *buf, size_t len, int cksum)
{
	uint16_t *sp = (uint16_t *)buf;
	int n, sn;
	
	sn = (int) len / 2;
	n = (sn + 15) / 16;

	/* XXX - unroll loop using Duff's device. */
	switch (sn % 16) {
	case 0:	do {
		cksum += *sp++;
	case 15:
		cksum += *sp++;
	case 14:
		cksum += *sp++;
	case 13:
		cksum += *sp++;
	case 12:
		cksum += *sp++;
	case 11:
		cksum += *sp++;
	case 10:
		cksum += *sp++;
	case 9:
		cksum += *sp++;
	case 8:
		cksum += *sp++;
	case 7:
		cksum += *sp++;
	case 6:
		cksum += *sp++;
	case 5:
		cksum += *sp++;
	case 4:
		cksum += *sp++;
	case 3:
		cksum += *sp++;
	case 2:
		cksum += *sp++;
	case 1:
		cksum += *sp++;
		} while (--n > 0);
	}
	if (len & 1)
		cksum += htons(*(u_char *)sp << 8);

	return (cksum);
}
