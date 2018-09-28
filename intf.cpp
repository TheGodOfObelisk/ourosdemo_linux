//sadly, we have to borrow it from libdnet
#include "intf.h"
#include "base.h"
#include "addr.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <memory.h>

//I don't know how these marco definitions work
//So I added all of them in case
//I have to suffer from it later inevitably
/* XXX - Tru64 */
#if defined(SIOCRIPMTU) && defined(SIOCSIPMTU)
# define SIOCGIFMTU SIOCRIPMTU
# define SIOCSIFMTU SIOCSIPMTU
#endif

/* XXX - HP-UX */
#if defined(SIOCADDIFADDR) && defined(SIOCDELIFADDR)
# define SIOCAIFADDR  SIOCADDIFADDR
# define SIOCDIFADDR  SIOCDELIFADDR
#endif

/* XXX - HP-UX, Solaris */
#if !defined(ifr_mtu) && defined(ifr_metric)
# define ifr_mtu  ifr_metric
#endif

#ifdef HAVE_SOCKADDR_SA_LEN
# define max(a, b) ((a) > (b) ? (a) : (b))
# define NEXTIFR(i) ((struct ifreq *) \
        max((u_char *)i + sizeof(struct ifreq), \
        (u_char *)&i->ifr_addr + i->ifr_addr.sa_len))
#else
# define NEXTIFR(i) (i + 1)
#endif

static u_int
intf_iff_to_flags(uint64_t iff)
{
  u_int n = 0;

  if (iff & IFF_UP)
    n |= INTF_FLAG_UP;  
  if (iff & IFF_LOOPBACK)
    n |= INTF_FLAG_LOOPBACK;
  if (iff & IFF_POINTOPOINT)
    n |= INTF_FLAG_POINTOPOINT;
  if (iff & IFF_NOARP)
    n |= INTF_FLAG_NOARP;
  if (iff & IFF_BROADCAST)
    n |= INTF_FLAG_BROADCAST;
  if (iff & IFF_MULTICAST)
    n |= INTF_FLAG_MULTICAST;
#ifdef IFF_IPMP
  /* Unset the BROADCAST and MULTICAST flags from Solaris IPMP interfaces,
   * otherwise _intf_set_type will think they are INTF_TYPE_ETH. */
  if (iff & IFF_IPMP)
    n &= ~(INTF_FLAG_BROADCAST | INTF_FLAG_MULTICAST);
#endif

  return (n);
}

/* XXX - this is total crap. how to do this without walking ifnet? */
static void
_intf_set_type(struct intf_entry *entry)
{
  if ((entry->intf_flags & INTF_FLAG_LOOPBACK) != 0)
    entry->intf_type = INTF_TYPE_LOOPBACK;
  else if ((entry->intf_flags & INTF_FLAG_BROADCAST) != 0)
    entry->intf_type = INTF_TYPE_ETH;
  else if ((entry->intf_flags & INTF_FLAG_POINTOPOINT) != 0)
    entry->intf_type = INTF_TYPE_TUN;
  else
    entry->intf_type = INTF_TYPE_OTHER;
}


//which _intf_get_noalias() should be used?
#ifdef SIOCGLIFCONF
int
_intf_get_noalias(intf_t *intf, struct intf_entry *entry)
{
  struct lifreq lifr;
  int fd;

  /* Get interface index. */
  entry->intf_index = if_nametoindex(entry->intf_name);
  if (entry->intf_index == 0)
    return (-1);

  strlcpy(lifr.lifr_name, entry->intf_name, sizeof(lifr.lifr_name));

  /* Get interface flags. Here he also check whether we need to use fd or
   * fd6 in the rest of the function. Using the wrong address family in
   * the ioctls gives ENXIO on Solaris. */
  if (ioctl(intf->fd, SIOCGLIFFLAGS, &lifr) >= 0)
    fd = intf->fd;
  else if (intf->fd6 != -1 && ioctl(intf->fd6, SIOCGLIFFLAGS, &lifr) >= 0)
    fd = intf->fd6;
  else
    return (-1);
  
  entry->intf_flags = intf_iff_to_flags(lifr.lifr_flags);
  _intf_set_type(entry);
  
  /* Get interface MTU. */
#ifdef SIOCGLIFMTU
  if (ioctl(fd, SIOCGLIFMTU, &lifr) < 0)
#endif
    return (-1);
  entry->intf_mtu = lifr.lifr_mtu;

  entry->intf_addr.addr_type = entry->intf_dst_addr.addr_type =
      entry->intf_link_addr.addr_type = ADDR_TYPE_NONE;
  
  /* Get primary interface address. */
  if (ioctl(fd, SIOCGLIFADDR, &lifr) == 0) {
    addr_ston((struct sockaddr *)&lifr.lifr_addr, &entry->intf_addr);
    if (ioctl(fd, SIOCGLIFNETMASK, &lifr) < 0)
      return (-1);
    addr_stob((struct sockaddr *)&lifr.lifr_addr, &entry->intf_addr.addr_bits);
  }
  /* Get other addresses. */
  if (entry->intf_type == INTF_TYPE_TUN) {
    if (ioctl(fd, SIOCGLIFDSTADDR, &lifr) == 0) {
      if (addr_ston((struct sockaddr *)&lifr.lifr_addr,
          &entry->intf_dst_addr) < 0)
        return (-1);
    }
  } else if (entry->intf_type == INTF_TYPE_ETH) {
    eth_t *eth;
    
    if ((eth = eth_open(entry->intf_name)) != NULL) {
      if (!eth_get(eth, &entry->intf_link_addr.addr_eth)) {
        entry->intf_link_addr.addr_type =
            ADDR_TYPE_ETH;
        entry->intf_link_addr.addr_bits =
            ETH_ADDR_BITS;
      }
      eth_close(eth);
    }
  }
  return (0);
}
#else//it seems that our compiler chooses the second function
static int
_intf_get_noalias(intf_t *intf, struct intf_entry *entry)
{
  struct ifreq ifr;
#ifdef HAVE_GETKERNINFO
  int size;
  struct kinfo_ndd *nddp;
  void *end;
#endif

  /* Get interface index. */
  entry->intf_index = if_nametoindex(entry->intf_name);
  if (entry->intf_index == 0)
    return (-1);

  strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));

  /* Get interface flags. */
  if (ioctl(intf->fd, SIOCGIFFLAGS, &ifr) < 0)
    return (-1);
  
  entry->intf_flags = intf_iff_to_flags(ifr.ifr_flags);
  _intf_set_type(entry);
  
  /* Get interface MTU. */
#ifdef SIOCGIFMTU
  if (ioctl(intf->fd, SIOCGIFMTU, &ifr) < 0)
#endif
    return (-1);
  entry->intf_mtu = ifr.ifr_mtu;

  entry->intf_addr.addr_type = entry->intf_dst_addr.addr_type =
      entry->intf_link_addr.addr_type = ADDR_TYPE_NONE;
  
  /* Get primary interface address. */
  if (ioctl(intf->fd, SIOCGIFADDR, &ifr) == 0) {
    addr_ston(&ifr.ifr_addr, &entry->intf_addr);
    if (ioctl(intf->fd, SIOCGIFNETMASK, &ifr) < 0)
      return (-1);
    addr_stob(&ifr.ifr_addr, &entry->intf_addr.addr_bits);
  }
  /* Get other addresses. */
  if (entry->intf_type == INTF_TYPE_TUN) {
    if (ioctl(intf->fd, SIOCGIFDSTADDR, &ifr) == 0) {
      if (addr_ston(&ifr.ifr_addr,
          &entry->intf_dst_addr) < 0)
        return (-1);
    }
  } else if (entry->intf_type == INTF_TYPE_ETH) {
#if defined(HAVE_GETKERNINFO)
    /* AIX also defines SIOCGIFHWADDR, but it fails silently?
     * This is the method IBM recommends here:
     * http://www-01.ibm.com/support/knowledgecenter/ssw_aix_53/com.ibm.aix.progcomm/doc/progcomc/skt_sndother_ex.htm%23ssqinc2joyc?lang=en
     */
    /* How many bytes will be returned? */
    size = getkerninfo(KINFO_NDD, 0, 0, 0);
    if (size <= 0) {
      return -1;
    }
    nddp = (struct kinfo_ndd *)malloc(size);

    if (!nddp) {
      return -1;
    }
    /* Get all Network Device Driver (NDD) info */
    if (getkerninfo(KINFO_NDD, nddp, &size, 0) < 0) {
      free(nddp);
      return -1;
    }
    /* Loop over the returned values until we find a match */
    end = (void *)nddp + size;
    while ((void *)nddp < end) {
      if (!strcmp(nddp->ndd_alias, entry->intf_name) ||
          !strcmp(nddp->ndd_name, entry->intf_name)) {
        addr_pack(&entry->intf_link_addr, ADDR_TYPE_ETH, ETH_ADDR_BITS,
            nddp->ndd_addr, ETH_ADDR_LEN);
        break;
      } else
        nddp++;
    }
    free(nddp);
#elif defined(SIOCGIFHWADDR)
    if (ioctl(intf->fd, SIOCGIFHWADDR, &ifr) < 0)
      return (-1);
    if (addr_ston(&ifr.ifr_addr, &entry->intf_link_addr) < 0) {
      /* Likely we got an unsupported address type. Just use NONE for now. */
      entry->intf_link_addr.addr_type = ADDR_TYPE_NONE;
      entry->intf_link_addr.addr_bits = 0;
    }
#elif defined(SIOCRPHYSADDR)
    /* Tru64 */
    struct ifdevea *ifd = (struct ifdevea *)&ifr; /* XXX */
    
    if (ioctl(intf->fd, SIOCRPHYSADDR, ifd) < 0)
      return (-1);
    addr_pack(&entry->intf_link_addr, ADDR_TYPE_ETH, ETH_ADDR_BITS,
        ifd->current_pa, ETH_ADDR_LEN);
#else
    eth_t *eth;
    
    if ((eth = eth_open(entry->intf_name)) != NULL) {
      if (!eth_get(eth, &entry->intf_link_addr.addr_eth)) {
        entry->intf_link_addr.addr_type =
            ADDR_TYPE_ETH;
        entry->intf_link_addr.addr_bits =
            ETH_ADDR_BITS;
      }
      eth_close(eth);
    }
#endif
  }
  return (0);
}
#endif

#ifdef SIOCLIFADDR
/* XXX - aliases on IRIX don't show up in SIOCGIFCONF */
static int
_intf_get_aliases(intf_t *intf, struct intf_entry *entry)
{
  struct dnet_ifaliasreq ifra;
  struct addr *ap, *lap;
  
  strlcpy(ifra.ifra_name, entry->intf_name, sizeof(ifra.ifra_name));
  addr_ntos(&entry->intf_addr, &ifra.ifra_addr);
  addr_btos(entry->intf_addr.addr_bits, &ifra.ifra_mask);
  memset(&ifra.ifra_brdaddr, 0, sizeof(ifra.ifra_brdaddr));
  ifra.ifra_cookie = 1;

  ap = entry->intf_alias_addrs;
  lap = (struct addr *)((u_char *)entry + entry->intf_len);
  
  while (ioctl(intf->fd, SIOCLIFADDR, &ifra) == 0 &&
      ifra.ifra_cookie > 0 && (ap + 1) < lap) {
    if (addr_ston(&ifra.ifra_addr, ap) < 0)
      break;
    ap++, entry->intf_alias_num++;
  }
  entry->intf_len = (u_char *)ap - (u_char *)entry;
  
  return (0);
}
#elif defined(SIOCGLIFCONF)
static int
_intf_get_aliases(intf_t *intf, struct intf_entry *entry)
{
  struct lifreq *lifr, *llifr;
  struct lifreq tmplifr;
  struct addr *ap, *lap;
  char *p;
  
  if (intf->lifc.lifc_len < (int)sizeof(*lifr)) {
    errno = EINVAL;
    return (-1);
  }
  entry->intf_alias_num = 0;
  ap = entry->intf_alias_addrs;
  llifr = (struct lifreq *)intf->lifc.lifc_buf + 
      (intf->lifc.lifc_len / sizeof(*llifr));
  lap = (struct addr *)((u_char *)entry + entry->intf_len);
  
  /* Get addresses for this interface. */
  for (lifr = intf->lifc.lifc_req; lifr < llifr && (ap + 1) < lap;
      lifr = NEXTLIFR(lifr)) {
    /* XXX - Linux, Solaris ifaliases */
    if ((p = strchr(lifr->lifr_name, ':')) != NULL)
      *p = '\0';
    
    if (strcmp(lifr->lifr_name, entry->intf_name) != 0) {
      if (p) *p = ':';
      continue;
    }
    
    /* Fix the name back up */
    if (p) *p = ':';

    if (addr_ston((struct sockaddr *)&lifr->lifr_addr, ap) < 0)
      continue;
    
    /* XXX */
    if (ap->addr_type == ADDR_TYPE_ETH) {
      memcpy(&entry->intf_link_addr, ap, sizeof(*ap));
      continue;
    } else if (ap->addr_type == ADDR_TYPE_IP) {
      if (ap->addr_ip == entry->intf_addr.addr_ip ||
          ap->addr_ip == entry->intf_dst_addr.addr_ip)
        continue;
      strlcpy(tmplifr.lifr_name, lifr->lifr_name, sizeof(tmplifr.lifr_name));
      if (ioctl(intf->fd, SIOCGIFNETMASK, &tmplifr) == 0)
        addr_stob((struct sockaddr *)&tmplifr.lifr_addr, &ap->addr_bits);
    } else if (ap->addr_type == ADDR_TYPE_IP6 && intf->fd6 != -1) {
      if (memcmp(&ap->addr_ip6, &entry->intf_addr.addr_ip6, IP6_ADDR_LEN) == 0 ||
          memcmp(&ap->addr_ip6, &entry->intf_dst_addr.addr_ip6, IP6_ADDR_LEN) == 0)
        continue;
      strlcpy(tmplifr.lifr_name, lifr->lifr_name, sizeof(tmplifr.lifr_name));
      if (ioctl(intf->fd6, SIOCGLIFNETMASK, &tmplifr) == 0) {
        addr_stob((struct sockaddr *)&tmplifr.lifr_addr,
            &ap->addr_bits);
      }
      else perror("SIOCGLIFNETMASK");
    }
    ap++, entry->intf_alias_num++;
  }
  entry->intf_len = (u_char *)ap - (u_char *)entry;
  
  return (0);
}
#else
static int
_intf_get_aliases(intf_t *intf, struct intf_entry *entry)
{
  struct ifreq *ifr, *lifr;
  struct ifreq tmpifr;
  struct addr *ap, *lap;
  char *p;
  
  if (intf->ifc.ifc_len < (int)sizeof(*ifr)) {
    errno = EINVAL;
    return (-1);
  }
  entry->intf_alias_num = 0;
  ap = entry->intf_alias_addrs;
  lifr = (struct ifreq *)intf->ifc.ifc_buf + 
      (intf->ifc.ifc_len / sizeof(*lifr));
  lap = (struct addr *)((u_char *)entry + entry->intf_len);
  
  /* Get addresses for this interface. */
  for (ifr = intf->ifc.ifc_req; ifr < lifr && (ap + 1) < lap;
      ifr = NEXTIFR(ifr)) {
    /* XXX - Linux, Solaris ifaliases */
    if ((p = strchr(ifr->ifr_name, ':')) != NULL)
      *p = '\0';
    
    if (strcmp(ifr->ifr_name, entry->intf_name) != 0) {
      if (p) *p = ':';
      continue;
    }
    
    /* Fix the name back up */
    if (p) *p = ':';

    if (addr_ston(&ifr->ifr_addr, ap) < 0)
      continue;
    
    /* XXX */
    if (ap->addr_type == ADDR_TYPE_ETH) {
      memcpy(&entry->intf_link_addr, ap, sizeof(*ap));
      continue;
    } else if (ap->addr_type == ADDR_TYPE_IP) {
      if (ap->addr_ip == entry->intf_addr.addr_ip ||
          ap->addr_ip == entry->intf_dst_addr.addr_ip)
        continue;
      strlcpy(tmpifr.ifr_name, ifr->ifr_name, sizeof(tmpifr.ifr_name));
      if (ioctl(intf->fd, SIOCGIFNETMASK, &tmpifr) == 0)
        addr_stob(&tmpifr.ifr_addr, &ap->addr_bits);
    }
#ifdef SIOCGIFNETMASK_IN6
    else if (ap->addr_type == ADDR_TYPE_IP6 && intf->fd6 != -1) {
      struct in6_ifreq ifr6;

      /* XXX - sizeof(ifr) < sizeof(ifr6) */
      memcpy(&ifr6, ifr, sizeof(ifr6));
      
      if (ioctl(intf->fd6, SIOCGIFNETMASK_IN6, &ifr6) == 0) {
        addr_stob((struct sockaddr *)&ifr6.ifr_addr,
            &ap->addr_bits);
      }
      else perror("SIOCGIFNETMASK_IN6");
    }
#else
#ifdef SIOCGIFNETMASK6
    else if (ap->addr_type == ADDR_TYPE_IP6 && intf->fd6 != -1) {
      struct in6_ifreq ifr6;

      /* XXX - sizeof(ifr) < sizeof(ifr6) */
      memcpy(&ifr6, ifr, sizeof(ifr6));
      
      if (ioctl(intf->fd6, SIOCGIFNETMASK6, &ifr6) == 0) {
        /* For some reason this is 0 after the ioctl. */
        ifr6.ifr_Addr.sin6_family = AF_INET6;
        addr_stob((struct sockaddr *)&ifr6.ifr_Addr,
            &ap->addr_bits);
      }
      else perror("SIOCGIFNETMASK6");
    }
#endif
#endif
    ap++, entry->intf_alias_num++;
  }
#ifdef HAVE_LINUX_PROCFS
#define PROC_INET6_FILE "/proc/net/if_inet6"
  {
    FILE *f;
    char buf[256], s[8][5], name[INTF_NAME_LEN];
    u_int idx, bits, scope, flags;
    
    if ((f = fopen(PROC_INET6_FILE, "r")) != NULL) {
      while (ap < lap &&
             fgets(buf, sizeof(buf), f) != NULL) {
        /* scan up to INTF_NAME_LEN-1 bytes to reserve space for null terminator */
        sscanf(buf, "%04s%04s%04s%04s%04s%04s%04s%04s %x %02x %02x %02x %15s\n",
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            &idx, &bits, &scope, &flags, name);
        if (strcmp(name, entry->intf_name) == 0) {
          snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
              s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bits);
          addr_aton(buf, ap);
          ap++, entry->intf_alias_num++;
        }
      }
      fclose(f);
    }
  }
#endif
  entry->intf_len = (u_char *)ap - (u_char *)entry;
  
  return (0);
}
#endif /* SIOCLIFADDR */

intf_t *
intf_open(void)
{
  intf_t *intf;
  int one = 1;
  
  if ((intf = (intf_t *)calloc(1, sizeof(*intf))) != NULL) {
    intf->fd = intf->fd6 = -1;
    
    if ((intf->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      return (intf_close(intf));

    setsockopt(intf->fd, SOL_SOCKET, SO_BROADCAST,
      (const char *) &one, sizeof(one));

#if defined(SIOCGLIFCONF) || defined(SIOCGIFNETMASK_IN6) || defined(SIOCGIFNETMASK6)
    if ((intf->fd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
#  ifdef EPROTONOSUPPORT
      if (errno != EPROTONOSUPPORT)
#  endif
        return (intf_close(intf));
    }
#endif
  }
  return (intf);
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
  if (_intf_get_noalias(intf, entry) < 0)
    return (-1);
#ifndef SIOCLIFADDR
  intf->ifc.ifc_buf = (caddr_t)intf->ifcbuf;
  intf->ifc.ifc_len = sizeof(intf->ifcbuf);
  
  if (ioctl(intf->fd, SIOCGIFCONF, &intf->ifc) < 0)
    return (-1);
#endif
  return (_intf_get_aliases(intf, entry));
  //return 1;//just test, which _intf_get_noalias() should I choose?
}


/* Look up an interface from an index, such as a sockaddr_in6.sin6_scope_id. */
int
intf_get_index(intf_t *intf, struct intf_entry *entry, int af, unsigned int index)
{
  char namebuf[IFNAMSIZ];
  char *devname;

  /* af is ignored; only used in intf-win32.c. */
  devname = if_indextoname(index, namebuf);
  if (devname == NULL)
    return (-1);
  strlcpy(entry->intf_name, devname, sizeof(entry->intf_name));
  return intf_get(intf, entry);
}

intf_t *
intf_close(intf_t *intf)
{
  if (intf != NULL) {
    if (intf->fd >= 0)
      close(intf->fd);
    if (intf->fd6 >= 0)
      close(intf->fd6);
    free(intf);
  }
  return (NULL);
}


#ifdef HAVE_LINUX_PROCFS
#define PROC_DEV_FILE "/proc/net/dev"

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
  FILE *fp;
  struct intf_entry *entry;
  char *p, buf[BUFSIZ], ebuf[BUFSIZ];
  int ret;

  entry = (struct intf_entry *)ebuf;
  
  if ((fp = fopen(PROC_DEV_FILE, "r")) == NULL)
    return (-1);
  
  intf->ifc.ifc_buf = (caddr_t)intf->ifcbuf;
  intf->ifc.ifc_len = sizeof(intf->ifcbuf);
  
  if (ioctl(intf->fd, SIOCGIFCONF, &intf->ifc) < 0) {
    fclose(fp);
    return (-1);
  }

  ret = 0;
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if ((p = strchr(buf, ':')) == NULL)
      continue;
    *p = '\0';
    for (p = buf; *p == ' '; p++)
      ;

    memset(ebuf, 0, sizeof(ebuf));
    strlcpy(entry->intf_name, p, sizeof(entry->intf_name));
    entry->intf_len = sizeof(ebuf);
    
    if (_intf_get_noalias(intf, entry) < 0) {
      ret = -1;
      break;
    }
    if (_intf_get_aliases(intf, entry) < 0) {
      ret = -1;
      break;
    }
    if ((ret = (*callback)(entry, arg)) != 0)
      break;
  }
  if (ferror(fp))
    ret = -1;
  
  fclose(fp);
  
  return (ret);
}
#elif defined(SIOCGLIFCONF)
int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
  struct intf_entry *entry;
  struct lifreq *lifr, *llifr, *plifr;
  char *p, ebuf[BUFSIZ];
  int ret;
  struct lifreq lifrflags;
  memset(&lifrflags, 0, sizeof(struct lifreq));

  entry = (struct intf_entry *)ebuf;

  /* http://www.unix.com/man-page/opensolaris/7p/if_tcp */
  intf->lifc.lifc_family = AF_UNSPEC;
  intf->lifc.lifc_flags = 0;
#ifdef LIFC_UNDER_IPMP
  intf->lifc.lifc_flags |= LIFC_UNDER_IPMP;
#endif
  intf->lifc.lifc_buf = (caddr_t)intf->ifcbuf;
  intf->lifc.lifc_len = sizeof(intf->ifcbuf);
  
  if (ioctl(intf->fd, SIOCGLIFCONF, &intf->lifc) < 0)
    return (-1);

  llifr = (struct lifreq *)&intf->lifc.lifc_buf[intf->lifc.lifc_len];
  
  for (lifr = intf->lifc.lifc_req; lifr < llifr; lifr = NEXTLIFR(lifr)) {
    /* XXX - Linux, Solaris ifaliases */
    if ((p = strchr(lifr->lifr_name, ':')) != NULL)
      *p = '\0';
    
    for (plifr = intf->lifc.lifc_req; plifr < lifr; plifr = NEXTLIFR(lifr)) {
      if (strcmp(lifr->lifr_name, plifr->lifr_name) == 0)
        break;
    }
    if (lifr > intf->lifc.lifc_req && plifr < lifr)
      continue;

    memset(ebuf, 0, sizeof(ebuf));
    strlcpy(entry->intf_name, lifr->lifr_name,
        sizeof(entry->intf_name));
    entry->intf_len = sizeof(ebuf);

    /* Repair the alias name back up */
    if (p) *p = ':';

    /* Ignore IPMP interfaces. These are virtual interfaces made up
     * of physical interfaces. IPMP interfaces do not support things
     * like packet sniffing; it is necessary to use one of the
     * underlying physical interfaces instead. This works as long as
     * the physical interface's test address is on the same subnet
     * as the IPMP interface's address. */
    strlcpy(lifrflags.lifr_name, lifr->lifr_name, sizeof(lifrflags.lifr_name));
    if (ioctl(intf->fd, SIOCGLIFFLAGS, &lifrflags) >= 0)
      ;
    else if (intf->fd6 != -1 && ioctl(intf->fd6, SIOCGLIFFLAGS, &lifrflags) >= 0)
      ;
    else
      return (-1);
#ifdef IFF_IPMP
    if (lifrflags.lifr_flags & IFF_IPMP) {
      continue;
    }
#endif
    
    if (_intf_get_noalias(intf, entry) < 0)
      return (-1);
    if (_intf_get_aliases(intf, entry) < 0)
      return (-1);
    
    if ((ret = (*callback)(entry, arg)) != 0)
      return (ret);
  }
  return (0);
}
#else
int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
  struct intf_entry *entry;
  struct ifreq *ifr, *lifr, *pifr;
  char *p, ebuf[BUFSIZ];
  int ret;

  entry = (struct intf_entry *)ebuf;

  intf->ifc.ifc_buf = (caddr_t)intf->ifcbuf;
  intf->ifc.ifc_len = sizeof(intf->ifcbuf);
  
  if (ioctl(intf->fd, SIOCGIFCONF, &intf->ifc) < 0)
    return (-1);

  pifr = NULL;
  lifr = (struct ifreq *)&intf->ifc.ifc_buf[intf->ifc.ifc_len];
  
  for (ifr = intf->ifc.ifc_req; ifr < lifr; ifr = NEXTIFR(ifr)) {
    /* XXX - Linux, Solaris ifaliases */
    if ((p = strchr(ifr->ifr_name, ':')) != NULL)
      *p = '\0';
    
    if (pifr != NULL && strcmp(ifr->ifr_name, pifr->ifr_name) == 0) {
      if (p) *p = ':';
      continue;
    }

    memset(ebuf, 0, sizeof(ebuf));
    strlcpy(entry->intf_name, ifr->ifr_name,
        sizeof(entry->intf_name));
    entry->intf_len = sizeof(ebuf);

    /* Repair the alias name back up */
    if (p) *p = ':';
    
    if (_intf_get_noalias(intf, entry) < 0)
      return (-1);
    if (_intf_get_aliases(intf, entry) < 0)
      return (-1);
    
    if ((ret = (*callback)(entry, arg)) != 0)
      return (ret);

    pifr = ifr;
  }
  return (0);
}
#endif /* !HAVE_LINUX_PROCFS */