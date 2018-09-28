#include "arp.h"
#include <stdlib.h>
#include <memory.h>
#include <sys/ioctl.h>
#include <unistd.h>
//borrowed from arp-bsd.c
//reconsider arp-none.c, arp-ioctl.c(1), arp-win32.c(no!)

/*
 * ARP ioctl request
 */
struct arpreq {
	struct	sockaddr arp_pa;		/* protocol address */
	struct	sockaddr arp_ha;		/* hardware address */
	int	arp_flags;			/* flags */
};

/*  arp_flags and at_flags field values */
#define	ATF_INUSE	0x01	/* entry in use */
#define ATF_COM		0x02	/* completed entry (enaddr valid) */
#define	ATF_PERM	0x04	/* permanent entry */
#define	ATF_PUBL	0x08	/* publish entry (respond for other host) */
#define	ATF_USETRAILERS	0x10	/* has requested trailers */


struct arp_handle {
	int	 fd;
#ifdef HAVE_ARPREQ_ARP_DEV
	intf_t	*intf;
#endif
};

arp_t *
arp_open(void)
{
	arp_t *a;
	
	if ((a = (arp_t*)calloc(1, sizeof(*a))) != NULL) {
#ifdef HAVE_STREAMS_MIB2
		if ((a->fd = open(IP_DEV_NAME, O_RDWR)) < 0)
#elif defined(HAVE_STREAMS_ROUTE)
		if ((a->fd = open("/dev/route", O_WRONLY, 0)) < 0)
#else
		if ((a->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
#endif
			return (arp_close(a));
#ifdef HAVE_ARPREQ_ARP_DEV
		if ((a->intf = intf_open()) == NULL)
			return (arp_close(a));
#endif
	}
	return (a);
}

int
arp_get(arp_t *a, struct arp_entry *entry)
{
	struct arpreq ar;

	memset(&ar, 0, sizeof(ar));
	
	if (addr_ntos(&entry->arp_pa, &ar.arp_pa) < 0)
		return (-1);
	
#ifdef HAVE_ARPREQ_ARP_DEV
	if (intf_loop(a->intf, _arp_set_dev, &ar) != 1) {
		errno = ESRCH;
		return (-1);
	}
#endif
	if (ioctl(a->fd, SIOCGARP, &ar) < 0)
		return (-1);

	if ((ar.arp_flags & ATF_COM) == 0) {
		errno = ESRCH;
		return (-1);
	}
	return (addr_ston(&ar.arp_ha, &entry->arp_ha));
}

arp_t *
arp_close(arp_t *a)
{
	if (a != NULL) {
		if (a->fd >= 0)
			close(a->fd);
#ifdef HAVE_ARPREQ_ARP_DEV
		if (a->intf != NULL)
			intf_close(a->intf);
#endif
		free(a);
	}
	return (NULL);
}
