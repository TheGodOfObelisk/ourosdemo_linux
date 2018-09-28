#ifndef DNET_ROUTE_H
#define DNET_ROUTE_H

#include "intf.h"
struct route_handle {
	int	 fd;
	int	 nlfd;
};


typedef struct route_handle route_t;
typedef int (*route_handler)(const struct route_entry *entry, void *arg);
/*
 * Routing table entry
 */
struct route_entry {
	char		intf_name[INTF_NAME_LEN];	/* interface name */
	struct addr	route_dst;	/* destination address */
	struct addr	route_gw;	/* gateway address */
	int		metric;		/* per-route metric */
};

//_BEGIN_DECLS
route_t	*route_open(void);
int	 route_loop(route_t *r, route_handler callback, void *arg);
route_t	*route_close(route_t *r);
//__END_DECLS
#endif /* DNET_ROUTE_H */