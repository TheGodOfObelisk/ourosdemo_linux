#include "ip6.h"
#include "addr.h"
#include "ip.h"
#include <stdlib.h>
int
ip6_pton(const char *p, ip6_addr_t *ip6)
{
	uint16_t data[8], *u = (uint16_t *)ip6->data;
	int i, j, n, z = -1;
	char *ep;
	long l;
	
	if (*p == ':')
		p++;
	
	for (n = 0; n < 8; n++) {
		l = strtol(p, &ep, 16);
		
		if (ep == p) {
			if (ep[0] == ':' && z == -1) {
				z = n;
				p++;
			} else if (ep[0] == '\0') {
				break;
			} else {
				return (-1);
			}
		} else if (ep[0] == '.' && n <= 6) {
			if (ip_pton(p, (ip_addr_t *)(data + n)) < 0)
				return (-1);
			n += 2;
			ep = ""; /* XXX */
			break;
		} else if (l >= 0 && l <= 0xffff) {
			data[n] = htons((uint16_t)l);

			if (ep[0] == '\0') {
				n++;
				break;
			} else if (ep[0] != ':' || ep[1] == '\0')
				return (-1);

			p = ep + 1;
		} else
			return (-1);
	}
	if (n == 0 || *ep != '\0' || (z == -1 && n != 8))
		return (-1);
	
	for (i = 0; i < z; i++) {
		u[i] = data[i];
	}
	while (i < 8 - (n - z - 1)) {
		u[i++] = 0;
	}
	for (j = z + 1; i < 8; i++, j++) {
		u[i] = data[j];
	}
	return (0);
}