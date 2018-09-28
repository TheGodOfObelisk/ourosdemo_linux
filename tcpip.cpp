#include "tcpip.h"
#include "scanops.h"
#include "errorhandle.h"
#include "tcp.h"
#include "udp.h"
#include "sctp.h"
#include "util.h"
#include "arp.h"
// #include <netinet/in.h>
#include "struct_ip.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

extern ScanOps o;
static PacketCounter PktCt;
/* Tries to resolve the given name (or literal IP) into a sockaddr structure.
   This function calls getaddrinfo and returns the same addrinfo linked list
   that getaddrinfo produces. Returns NULL for any error or failure to resolve.
   You need to call freeaddrinfo on the result if non-NULL. */
struct addrinfo *resolve_all(const char *hostname, int pf) {
  struct addrinfo hints;
  struct addrinfo *result;
  int rc;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  /* Otherwise we get multiple identical addresses with different socktypes. */
  hints.ai_socktype = SOCK_DGRAM;
  rc = getaddrinfo(hostname, NULL, &hints, &result);
  if (rc != 0){
    if (o.debugging > 1)
      error("Error resolving %s: %s", hostname, gai_strerror(rc));
    return NULL;
  }

  return result;
}

/* Takes a destination address (dst) and tries to determine the
   source address and interface necessary to route to this address.
   If no route is found, false is returned and rnfo is undefined.  If
   a route is found, true is returned and rnfo is filled in with all
   of the routing details.  This function takes into account -S and -e
   options set by user (o.spoofsource, o.device) */
int nmap_route_dst(const struct sockaddr_storage *dst, struct route_nfo *rnfo){
  struct sockaddr_storage spoofss;
  size_t spoofsslen;

  if (o.spoofsource) {
    o.SourceSockAddr(&spoofss, &spoofsslen);
    return route_dst(dst, rnfo, o.device, &spoofss);
  } else {
    return route_dst(dst, rnfo, o.device, NULL);
  }
}

/* Create a raw socket and do things that always apply to raw sockets:
    * Set SO_BROADCAST.
    * Set IP_HDRINCL.
    * Bind to an interface with SO_BINDTODEVICE (if o.device is set).
   The socket is created with address family AF_INET, but may be usable for
   AF_INET6, depending on the operating system. */
int nmap_raw_socket() {
  int rawsd;

  rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (rawsd < 0)
    return rawsd;
  broadcast_socket(rawsd);
#ifndef WIN32
  sethdrinclude(rawsd);
#endif
  socket_bindtodevice(rawsd, o.device);

  return rawsd;
}

/* Give broadcast permission to a socket */
void broadcast_socket(int sd) {
  int one = 1;
#ifdef WIN32
  if (sd == 501)
    return;
#endif
  if (setsockopt (sd, SOL_SOCKET, SO_BROADCAST, (const char *) &one, sizeof(int)) != 0) {
    error("Failed to secure socket broadcasting permission");
    perror("setsockopt");
  }
}

// Returns whether the packet receive time value obtained from libpcap
// (and thus by readip_pcap()) should be considered valid.  When
// invalid (Windows and Amiga), readip_pcap returns the time you called it.
bool pcap_recv_timeval_valid() {
#if defined(WIN32) || defined(__amigaos__)
  return false;
#else
  return true;
#endif
}

/* Converts an IP address given in a sockaddr_storage to an IPv4 or
   IPv6 IP address string.  Since a static buffer is returned, this is
   not thread-safe and can only be used once in calls like printf() */
const char *inet_socktop(struct sockaddr_storage *ss) {
  static char buf[INET6_ADDRSTRLEN];
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
#endif

  if (inet_ntop(sin->sin_family, (sin->sin_family == AF_INET) ?
                (char *) &sin->sin_addr :
#if HAVE_IPV6
                (char *) &sin6->sin6_addr,
#else
                (char *) NULL,
#endif /* HAVE_IPV6 */
                buf, sizeof(buf)) == NULL) {
    fatal("Failed to convert target address to presentation format in %s!?!  Error: %s", __func__, strerror(socket_errno()));
  }
  return buf;
}

/* Returns a buffer of ASCII information about a packet that may look
   like "TCP 127.0.0.1:50923 > 127.0.0.1:3 S ttl=61 id=39516 iplen=40
   seq=625950769" or "ICMP PING (0/1) ttl=61 id=39516 iplen=40".
   IMPORTANT: This is a wrapper for function ippackethdrinfo(). Check
   nbase/nbase_net.c for details on the returned buffer. */
static const char *nmap_format_ippacket(const u8 *packet, u32 len) {
  int detail = LOW_DETAIL;
  if (o.debugging == 2) {
    detail = MEDIUM_DETAIL;
  } else if (o.debugging >= 3) {
    detail = HIGH_DETAIL;
  }
  return ippackethdrinfo(packet, len, detail);
}


/* Takes an IP PACKET and prints it if packet tracing is enabled.
   'packet' must point to the IPv4 header. The direction must be
   PacketTrace::SENT or PacketTrace::RCVD .  Optional 'now' argument
   makes this function slightly more efficient by avoiding a gettimeofday()
   call. */
void PacketTrace::trace(pdirection pdir, const u8 *packet, u32 len,
                        struct timeval *now) {
  struct timeval tv;

  if (pdir == SENT) {
    PktCt.sendPackets++;
    PktCt.sendBytes += len;
  } else {
    PktCt.recvPackets++;
    PktCt.recvBytes += len;
  }

  if (!o.packetTrace())
    return;

  if (now)
    tv = *now;
  else
    gettimeofday(&tv, NULL);

  if (len < 20) {
    error("Packet tracer: tiny packet encountered");
    return;
  }

  // log_write(LOG_STDOUT | LOG_NORMAL, "%s (%.4fs) %s\n",
  //           (pdir == SENT) ? "SENT" : "RCVD",
  //           o.TimeSinceStart(&tv), nmap_format_ippacket(packet, len));
  printf("%s (%.4fs) %s\n",
            (pdir == SENT) ? "SENT" : "RCVD",
            o.TimeSinceStart(&tv), nmap_format_ippacket(packet, len));

  return;
}

/* Adds a trace entry when a connect() is attempted if packet tracing
   is enabled.  Pass IPPROTO_TCP or IPPROTO_UDP as the protocol.  The
   sock may be a sockaddr_in or sockaddr_in6.  The return code of
   connect is passed in connectrc.  If the return code is -1, get the
   errno and pass that as connect_errno. */
void PacketTrace::traceConnect(u8 proto, const struct sockaddr *sock,
                               int socklen, int connectrc,
                               int connect_errno,
                               const struct timeval *now) {
  struct sockaddr_in *sin = (struct sockaddr_in *) sock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sock;
#endif
  struct timeval tv;
  char errbuf[64] = "";
  char targetipstr[INET6_ADDRSTRLEN] = "";
  u16 targetport = 0;

  if (!o.packetTrace())
    return;

  if (now)
    tv = *now;
  else
    gettimeofday(&tv, NULL);

  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if (connectrc == 0) {
    Strncpy(errbuf, "Connected", sizeof(errbuf));
  }
#if WIN32
  else if (connect_errno == WSAEWOULDBLOCK) {
    /* Special case for WSAEWOULDBLOCK. socket_strerror returns the unwieldy
       "A non-blocking socket operation could not be completed immediately." */
    Strncpy(errbuf, "Operation now in progress", sizeof(errbuf));
  }
#endif
  else {
    Snprintf(errbuf, sizeof(errbuf), "%s", socket_strerror(connect_errno));
  }

  if (sin->sin_family == AF_INET) {
    if (inet_ntop(sin->sin_family, (char *) &sin->sin_addr, targetipstr,
                  sizeof(targetipstr)) == NULL)
      fatal("Failed to convert target IPv4 address to presentation format!?!");
    targetport = ntohs(sin->sin_port);
  } else {
#if HAVE_IPV6
    assert(sin->sin_family == AF_INET6);
    if (inet_ntop(sin->sin_family, (char *) &sin6->sin6_addr, targetipstr,
                  sizeof(targetipstr)) == NULL)
      fatal("Failed to convert target IPv6 address to presentation format!?!");
    targetport = ntohs(sin6->sin6_port);
#else
    assert(0);
#endif
  }

  // log_write(LOG_STDOUT | LOG_NORMAL,
  //           "CONN (%.4fs) %s localhost > %s:%d => %s\n",
  //           o.TimeSinceStart(&tv),
  //           (proto == IPPROTO_TCP) ? "TCP" : "UDP", targetipstr,
  //           targetport, errbuf);
  printf("CONN (%.4fs) %s localhost > %s:%d => %s\n",
            o.TimeSinceStart(&tv),
            (proto == IPPROTO_TCP) ? "TCP" : "UDP", targetipstr,
            targetport, errbuf);
}

/* Return an IPv4 pseudoheader checksum for the given protocol and data. Unlike
   ipv4_pseudoheader_cksum, this knows about STUPID_SOLARIS_CHECKSUM_BUG and
   takes care of o.badsum. */
static u16 ipv4_cksum(const struct in_addr *src, const struct in_addr *dst,
                      u8 proto, const void *data, u16 len) {
  u16 sum;

// #if STUPID_SOLARIS_CHECKSUM_BUG
//   sum = len;
// #else
  sum = ipv4_pseudoheader_cksum(src, dst, proto, len, data);
// #endif

  if (o.badsum) {
    --sum;
    if (proto == IPPROTO_UDP && sum == 0)
      sum = 0xffff; // UDP checksum=0 means no checksum
  }

  return sum;
}

/* Build a TCP packet (no IP header). Sets tcp->th_sum to 0 so it can be filled
   in by a function with knowledge of the higher-level pseudoheader. */
static u8 *build_tcp(u16 sport, u16 dport, u32 seq, u32 ack, u8 reserved,
                     u8 flags, u16 window, u16 urp,
                     const u8 *tcpopt, int tcpoptlen,
                     const char *data, u16 datalen, u32 *packetlen) {
  struct tcp_hdr *tcp;
  u8 *packet;

  if (tcpoptlen % 4 != 0)
    fatal("%s called with an option length argument of %d which is illegal because it is not divisible by 4. Just add \\0 padding to the end.", __func__, tcpoptlen);

  *packetlen = sizeof(*tcp) + tcpoptlen + datalen;
  packet = (u8 *) safe_malloc(*packetlen);
  tcp = (struct tcp_hdr *) packet;

  memset(tcp, 0, sizeof(*tcp));
  tcp->th_sport = htons(sport);
  tcp->th_dport = htons(dport);

  if (seq)
    tcp->th_seq = htonl(seq);
  else if (flags & TH_SYN)
    get_random_bytes(&(tcp->th_seq), 4);

  if (ack)
    tcp->th_ack = htonl(ack);

  if (reserved)
    tcp->th_x2 = reserved & 0x0F;
  tcp->th_off = 5 + (tcpoptlen / 4); /* words */
  tcp->th_flags = flags;

  if (window)
    tcp->th_win = htons(window);
  else
    tcp->th_win = htons(1024); /* Who cares */

  if (urp)
    tcp->th_urp = htons(urp);

  /* And the options */
  if (tcpoptlen)
    memcpy(packet + sizeof(*tcp), tcpopt, tcpoptlen);

  /* We should probably copy the data over too */
  if (data && datalen)
    memcpy(packet + sizeof(*tcp) + tcpoptlen, data, datalen);

  tcp->th_sum = 0;

  return packet;
}

/* Builds a TCP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_tcp_raw(const struct in_addr *source,
                  const struct in_addr *victim, int ttl, u16 ipid, u8 tos,
                  bool df, const u8 *ipopt, int ipoptlen, u16 sport, u16 dport,
                  u32 seq, u32 ack, u8 reserved, u8 flags, u16 window,
                  u16 urp, const u8 *tcpopt, int tcpoptlen, const char *data,
                  u16 datalen, u32 *packetlen) {
  struct tcp_hdr *tcp;
  u32 tcplen;
  u8 *ip;

  tcp = (struct tcp_hdr *) build_tcp(sport, dport, seq, ack, reserved, flags,
                                     window, urp, tcpopt, tcpoptlen, data, datalen, &tcplen);
  tcp->th_sum = ipv4_cksum(source, victim, IPPROTO_TCP, tcp, tcplen);
  ip = build_ip_raw(source, victim, IPPROTO_TCP, ttl, ipid, tos, df,
                    ipopt, ipoptlen, (char *) tcp, tcplen, packetlen);
  free(tcp);

  return ip;
}

// fill ip header. no error check.
// This function is also changing what's needed from host to network order.
static inline int fill_ip_raw(struct ip *ip, int packetlen, const u8 *ipopt,
                              int ipoptlen, int tos, int id,
                              int off, int ttl, int p,
                              const struct in_addr *ip_src,
                              const struct in_addr *ip_dst) {
  ip->ip_v = 4;
  ip->ip_hl = 5 + (ipoptlen / 4);
  ip->ip_tos = tos;
  ip->ip_len = htons(packetlen);
  ip->ip_id = htons(id);
  ip->ip_off = htons(off);
  ip->ip_ttl = ttl;
  ip->ip_p = p;
  ip->ip_src.s_addr = ip_src->s_addr;
  ip->ip_dst.s_addr = ip_dst->s_addr;

  if (ipoptlen)
    memcpy((u8 *) ip + sizeof(struct ip), ipopt, ipoptlen);

  // ip options source routing hack:
  if (ipoptlen && o.ipopt_firsthop && o.ipopt_lasthop) {
    u8 *ipo = (u8 *) ip + sizeof(struct ip);
    struct in_addr *newdst = (struct in_addr *) &ipo[o.ipopt_firsthop];
    struct in_addr *olddst = (struct in_addr *) &ipo[o.ipopt_lasthop];
    // our destination is somewhere else :)
    ip->ip_dst.s_addr = newdst->s_addr;

    // and last hop should be destination
    olddst->s_addr = ip_dst->s_addr;
  }
//attention!
// #if HAVE_IP_IP_SUM
  ip->ip_sum = 0;
  ip->ip_sum = in_cksum((unsigned short *) ip, sizeof(struct ip) + ipoptlen);
// #endif
  return (sizeof(struct ip) + ipoptlen);
}


/* Builds an IP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_ip_raw(const struct in_addr *source,
                 const struct in_addr *victim, u8 proto, int ttl,
                 u16 ipid, u8 tos, bool df, const u8 *ipopt, int ipoptlen,
                 const char *data, u16 datalen, u32 *outpacketlen) {
  int packetlen = sizeof(struct ip) + ipoptlen + datalen;
  u8 *packet = (u8 *) safe_malloc(packetlen);
  struct ip *ip = (struct ip *) packet;
  static int myttl = 0;

  /* check that required fields are there and not too silly */
  assert(source);
  assert(victim);
  assert(ipoptlen % 4 == 0);

  /* Time to live */
  if (ttl == -1) {
    myttl = (get_random_uint() % 23) + 37;
  } else {
    myttl = ttl;
  }

  fill_ip_raw(ip, packetlen, ipopt, ipoptlen,
              tos, ipid, df ? IP_DF : 0, myttl, proto, source, victim);

  /* We should probably copy the data over too */
  if (data && datalen)
    memcpy((u8 *) ip + sizeof(struct ip) + ipoptlen, data, datalen);

  *outpacketlen = packetlen;
  return packet;
}

/* Send a pre-built IPv4 packet. Handles fragmentation and whether to send with
   an ethernet handle or a socket. */
static int send_ipv4_packet(int sd, const struct eth_nfo *eth,
                            const struct sockaddr_in *dst,
                            const u8 *packet, unsigned int packetlen) {
  struct ip *ip = (struct ip *) packet;
  int res;

  assert(packet);
  assert((int) packetlen > 0);

  /* Fragmentation requested && packet is bigger than MTU */
  if (o.fragscan && !(ntohs(ip->ip_off) & IP_DF) &&
      (packetlen - ip->ip_hl * 4 > (unsigned int) o.fragscan)) {
    res = send_frag_ip_packet(sd, eth, dst, packet, packetlen, o.fragscan);
  } else {
    res = send_ip_packet_eth_or_sd(sd, eth, dst, packet, packetlen);
  }
  if (res != -1)
    PacketTrace::trace(PacketTrace::SENT, packet, packetlen);

  return res;
}

int send_ip_packet(int sd, const struct eth_nfo *eth,
                   const struct sockaddr_storage *dst,
                   const u8 *packet, unsigned int packetlen) {
  struct ip *ip = (struct ip *) packet;

  /* Ensure there's enough to read ip->ip_v at least. */
  if (packetlen < 1)
    return -1;

  if (ip->ip_v == 4) {
    assert(dst->ss_family == AF_INET);
    return send_ipv4_packet(sd, eth, (struct sockaddr_in *) dst, packet, packetlen);
  } /*else if (ip->ip_v == 6) {
    assert(dst->ss_family == AF_INET6);
    return send_ipv6_packet(sd, eth, (struct sockaddr_in6 *) dst, packet, packetlen);
  }*///suppose we do not use ipv6

  fatal("%s only understands IP versions 4 and 6 (got %u)", __func__, ip->ip_v);
}

/* Build a UDP packet (no IP header). Sets udp->uh_sum to 0 so it can be filled
   in by a function with knowledge of the higher-level pseudoheader. */
static u8 *build_udp(u16 sport, u16 dport, const char *data, u16 datalen,
                     u32 *packetlen) {
  struct udp_hdr *udp;
  u8 *packet;

  *packetlen = sizeof(*udp) + datalen;
  packet = (u8 *) safe_malloc(*packetlen);
  udp = (struct udp_hdr *) packet;

  memset(udp, 0, sizeof(*udp));
  udp->uh_sport = htons(sport);
  udp->uh_dport = htons(dport);

  udp->uh_ulen = htons(*packetlen);
  if (data && datalen)
    memcpy(packet + sizeof(*udp), data, datalen);

  udp->uh_sum = 0;

  return packet;
}

/* Builds a UDP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_udp_raw(const struct in_addr *source, const struct in_addr *victim,
                  int ttl, u16 ipid, u8 tos, bool df,
                  u8 *ipopt, int ipoptlen,
                  u16 sport, u16 dport,
                  const char *data, u16 datalen, u32 *packetlen) {
  struct udp_hdr *udp;
  u32 udplen;
  u8 *ip;

  udp = (struct udp_hdr *) build_udp(sport, dport, data, datalen, &udplen);
  udp->uh_sum = ipv4_cksum(source, victim, IPPROTO_UDP, udp, udplen);
  ip = build_ip_raw(source, victim, IPPROTO_UDP, ttl, ipid, tos, df,
                    ipopt, ipoptlen, (char *) udp, udplen, packetlen);
  free(udp);

  return ip;
}

/* Build an SCTP packet (no IP header). */
static u8 *build_sctp(u16 sport, u16 dport, u32 vtag,
                      const char *chunks, int chunkslen,
                      const char *data, u16 datalen,
                      u32 *packetlen) {
  struct sctp_hdr *sctp;
  u8 *packet;

  *packetlen = sizeof(*sctp) + chunkslen + datalen;
  packet = (u8 *) safe_malloc(*packetlen);
  sctp = (struct sctp_hdr *) packet;

  sctp->sh_sport = htons(sport);
  sctp->sh_dport = htons(dport);
  sctp->sh_sum = 0;
  sctp->sh_vtag = htonl(vtag);

  if (chunks)
    memcpy(packet + sizeof(*sctp), chunks, chunkslen);

  if (data)
    memcpy(packet + sizeof(*sctp) + chunkslen, data, datalen);

  /* RFC 2960 originally defined Adler32 checksums, which was later
   * revised to CRC32C in RFC 3309 and RFC 4960 respectively.
   * Nmap uses CRC32C by default, unless --adler32 is given. */
  if (o.adler32)
    sctp->sh_sum = htonl(nbase_adler32(packet, *packetlen));
  else
    sctp->sh_sum = htonl(nbase_crc32c(packet, *packetlen));

  if (o.badsum)
    --sctp->sh_sum;

  return packet;
}


/* Builds an SCTP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_sctp_raw(const struct in_addr *source,
                   const struct in_addr *victim, int ttl, u16 ipid,
                   u8 tos, bool df, u8 *ipopt, int ipoptlen, u16 sport,
                   u16 dport, u32 vtag, char *chunks, int chunkslen,
                   const char *data, u16 datalen, u32 *packetlen) {
  u8 *ip, *sctp;
  u32 sctplen;

  sctp = build_sctp(sport, dport, vtag, chunks, chunkslen, data, datalen, &sctplen);
  ip = build_ip_raw(source, victim, IPPROTO_SCTP, ttl, ipid, tos, df,
                    ipopt, ipoptlen, (char *) sctp, sctplen, packetlen);
  free(sctp);

  return ip;
}

/* Builds an ICMP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer.  The id/seq will be converted
   to network byte order (if it differs from HBO) */
u8 *build_icmp_raw(const struct in_addr *source,
                   const struct in_addr *victim, int ttl, u16 ipid,
                   u8 tos, bool df, u8 *ipopt, int ipoptlen, u16 seq,
                   unsigned short id, u8 ptype, u8 pcode, const char *data,
                   u16 datalen, u32 *packetlen) {
  struct ppkt {
    u8 type;
    u8 code;
    u16 checksum;
    u16 id;
    u16 seq;
    u8 data[1500]; /* Note -- first 4-12 bytes can be used for ICMP header */
  } pingpkt;
  u8 *datastart = pingpkt.data;
  /* dlen is the amount of space remaining in the data buffer; it may be reduced
     depending on type. */
  int dlen = sizeof(pingpkt.data);
  int icmplen = 0;
  char *ping = (char *) &pingpkt;

  pingpkt.type = ptype;
  pingpkt.code = pcode;

  if (ptype == 8) {
    /* echo request */
    icmplen = 8;
  } else if (ptype == 13 && pcode == 0) {
    /* ICMP timestamp req */
    icmplen = 20;
    memset(datastart, 0, 12);
    datastart += 12;
    dlen -= 12;
  } else if (ptype == 17 && pcode == 0) {
    /* icmp netmask req */
    icmplen = 12;
    memset(datastart, 0, 4);
    datastart += 4;
    dlen -= 4;
  } else {
    fatal("Unknown icmp type/code (%d/%d) in %s", ptype, pcode, __func__);
  }

  /* Copy the data over too */
  if (datalen > 0) {
    icmplen += MIN(dlen, datalen);
    if (data == NULL)
      memset(datastart, 0, MIN(dlen, datalen));
    else
      memcpy(datastart, data, MIN(dlen, datalen));
  }

  /* Fill out the ping packet. All the ICMP types handled by this function have
     the id and seq fields. */
  pingpkt.id = htons(id);
  pingpkt.seq = htons(seq);
  pingpkt.checksum = 0;
  pingpkt.checksum = in_cksum((unsigned short *) ping, icmplen);

  if (o.badsum)
    --pingpkt.checksum;

  return build_ip_raw(source, victim, IPPROTO_ICMP, ttl, ipid, tos, df,
                      ipopt, ipoptlen, ping, icmplen, packetlen);
}


/* Builds an IGMP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in packetlen,
   which must be a valid int pointer. */
u8 *build_igmp_raw(const struct in_addr *source,
                   const struct in_addr *victim, int ttl, u16 ipid,
                   u8 tos, bool df, u8 *ipopt, int ipoptlen, u8 ptype,
                   u8 pcode, const char *data, u16 datalen, u32 *packetlen) {
  struct {
    u8 igmp_type;
    u8 igmp_code;
    u16 igmp_cksum;
    u32 var; /* changes between types, unused. usually group address. */
    u8 data[1500];
  } igmp;
  u32 *datastart = (u32 *) igmp.data;
  int dlen = sizeof(igmp.data);
  int igmplen = 0;
  char *pkt = (char *) &igmp;

  igmp.igmp_type = ptype;
  igmp.igmp_code = pcode;

  if (ptype == 0x11) {
    /* Membership Query */
    igmplen = 8;
  } else if (ptype == 0x12) {
    /* v1 Membership Report */
    igmplen = 8;
  } else if (ptype == 0x16) {
    /* v2 Membership Report */
    igmplen = 8;
  } else if (ptype == 0x17) {
    /* v2 Leave Group */
    igmplen = 8;
  } else if (ptype == 0x22) {
    /* v3 Membership Report */
    igmplen = 8;
  } else {
    fatal("Unknown igmp type (%d) in %s", ptype, __func__);
  }

  if (datalen > 0) {
    igmplen += MIN(dlen, datalen);
    if (data == NULL)
      memset(datastart, 0, MIN(dlen, datalen));
    else
      memcpy(datastart, data, MIN(dlen, datalen));
  }

  igmp.igmp_cksum = 0;
  igmp.igmp_cksum = in_cksum((unsigned short *) pkt, igmplen);

  if (o.badsum)
    --igmp.igmp_cksum;

  return build_ip_raw(source, victim, IPPROTO_IGMP, ttl, ipid, tos, df,
                      ipopt, ipoptlen, pkt, igmplen, packetlen);
}

/* Takes an ARP PACKET (not including ethernet header) and
   prints it if packet tracing is enabled. The
   direction must be PacketTrace::SENT or PacketTrace::RCVD .
   Optional 'now' argument makes this function slightly more
   efficient by avoiding a gettimeofday() call. */
void PacketTrace::traceArp(pdirection pdir, const u8 *frame, u32 len,
                           struct timeval *now) {
  struct timeval tv;
  char arpdesc[128];
  char who_has[INET_ADDRSTRLEN], tell[INET_ADDRSTRLEN];

  if (pdir == SENT) {
    PktCt.sendPackets++;
    PktCt.sendBytes += len;
  } else {
    PktCt.recvPackets++;
    PktCt.recvBytes += len;
  }

  if (!o.packetTrace())
    return;

  if (now)
    tv = *now;
  else
    gettimeofday(&tv, NULL);

  if (len < 28) {
    error("Packet tracer: Arp packets must be at least 28 bytes long.  Should be exactly that length excl. ethernet padding.");
    return;
  }

  if (frame[7] == 1) { /* arp REQUEST */
    inet_ntop(AF_INET, (void *)(frame + 24), who_has, sizeof(who_has));
    inet_ntop(AF_INET, (void *)(frame + 14), tell, sizeof(tell));
    Snprintf(arpdesc, sizeof(arpdesc), "who-has %s tell %s", who_has, tell);
  } else { /* ARP REPLY */
    inet_ntop(AF_INET, (void *)(frame + 14), who_has, sizeof(who_has));
    Snprintf(arpdesc, sizeof(arpdesc),
             "reply %s is-at %02X:%02X:%02X:%02X:%02X:%02X", who_has,
             frame[8], frame[9], frame[10], frame[11], frame[12],
             frame[13]);
  }

  // log_write(LOG_STDOUT | LOG_NORMAL, "%s (%.4fs) ARP %s\n",
  //           (pdir == SENT) ? "SENT" : "RCVD",
  //           o.TimeSinceStart(&tv), arpdesc);
    printf("%s (%.4fs) ARP %s\n",
            (pdir == SENT) ? "SENT" : "RCVD",
            o.TimeSinceStart(&tv), arpdesc);

  return;
}

/* Used by validatepkt() to validate the TCP header (including option lengths).
   The options checked are MSS, WScale, SackOK, Sack, and Timestamp. */
static bool validateTCPhdr(u8 *tcpc, unsigned len) {
  struct tcp_hdr *tcp = (struct tcp_hdr *) tcpc;
  unsigned hdrlen, optlen;

  hdrlen = tcp->th_off * 4;

  /* Check header length */
  if (hdrlen > len || hdrlen < sizeof(struct tcp_hdr))
    return false;

  /* Get to the options */
  tcpc += sizeof(struct tcp_hdr);
  optlen = hdrlen - sizeof(struct tcp_hdr);

  while (optlen > 0) {
    switch (*tcpc) {
    case 2: /* MSS */
      if (optlen < 4)
        return false;
      optlen -= 4;
      tcpc += 4;
      break;
    case 3: /* Window Scale */
      if (optlen < 3)
        return false;
      optlen -= 3;
      tcpc += 3;
      break;
    case 4: /* SACK Permitted */
      if (optlen < 2)
        return false;
      optlen -= 2;
      tcpc += 2;
      break;
    case 5: /* SACK */
      if (optlen < *++tcpc)
        return false;
      if (!(*tcpc - 2) || ((*tcpc - 2) % 8))
        return false;
      optlen -= *tcpc;
      tcpc += (*tcpc - 1);
      break;
    case 8: /* Timestamp */
      if (optlen < 10)
        return false;
      optlen -= 10;
      tcpc += 10;
      break;
    case 14: /* Alternate checksum */
      /* Sometimes used for hardware checksum offloading
       * ftp://ftp.ucsd.edu/pub/csl/fastnet/faq.txt
       */
      if (optlen < 3)
        return false;
      optlen -= 3;
      tcpc += 3;
      break;
    default:
      optlen--;
      tcpc++;
      break;
    }
  }

  return true;
}


/* Used by readip_pcap() to validate an IP packet.  It checks to make sure:
 *
 * 1) there is enough room for an IP header in the amount of bytes read
 * 2) the IP version number is correct
 * 3) the IP length fields are at least as big as the standard header
 * 4) the IP packet received isn't a fragment, or is the initial fragment
 * 5) that next level headers seem reasonable (e.g. validateTCPhdr())
 *
 * Checking the IP total length (iplen) to see if its at least as large as the
 * number of bytes read (len) does not work because things like the Ethernet
 * CRC also get captured and are counted in len.  However, since the IP total
 * length field can't be trusted, we use len instead of iplen when doing any
 * further checks on lengths.  readip_pcap fixes the length on it's end if we
 * read more than the IP header says we should have so as to not pass garbage
 * data to the caller.
 */
static bool validatepkt(u8 *ipc, unsigned *len) {
  struct ip *ip = (struct ip *) ipc;
  const void *data;
  unsigned int datalen, iplen;
  u8 hdr;

  if (*len < 1) {
    if (o.debugging >= 3)
      error("Rejecting tiny, supposed IP packet (size %u)", *len);
    return false;
  }

  if (ip->ip_v == 4) {
    unsigned fragoff, iplen;

    datalen = *len;
    data = ipv4_get_data(ip, &datalen);
    if (data == NULL) {
      if (o.debugging >= 3)
        error("Rejecting IP packet because of invalid length");
      return false;
    }

    iplen = ntohs(ip->ip_len);

    fragoff = 8 * (ntohs(ip->ip_off) & IP_OFFMASK);
    if (fragoff) {
      if (o.debugging >= 3)
        error("Rejecting IP fragment (offset %u)", fragoff);
      return false;
    }

    /* OK, since the IP header has been validated, we don't want to tell
     * the caller they have more packet than they really have.  This can
     * be caused by the Ethernet CRC trailer being counted, for example. */
    if (*len > iplen)
      *len = iplen;

    hdr = ip->ip_p;
  } /*else if (ip->ip_v == 6) {
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) ipc;

    datalen = *len;
    data = ipv6_get_data(ip6, &datalen, &hdr);
    if (data == NULL) {
      if (o.debugging >= 3)
        error("Rejecting IP packet because of invalid length");
      return false;
    }

    iplen = ntohs(ip6->ip6_plen);
    if (datalen > iplen)
      *len -= datalen - iplen;
  } */
    //we do not need ipv6
    else {
    if (o.debugging >= 3)
      error("Rejecting IP packet because of invalid version number %u", ip->ip_v);
    return false;
  }

  switch (hdr) {
  case IPPROTO_TCP:
    if (datalen < sizeof(struct tcp_hdr)) {
      if (o.debugging >= 3)
        error("Rejecting TCP packet because of incomplete header");
      return false;
    }
    if (!validateTCPhdr((u8 *) data, datalen)) {
      if (o.debugging >= 3)
        error("Rejecting TCP packet because of bad TCP header");
      return false;
    }
    break;
  case IPPROTO_UDP:
    if (datalen < sizeof(struct udp_hdr)) {
      if (o.debugging >= 3)
        error("Rejecting UDP packet because of incomplete header");
      return false;
    }
    break;
  default:
    break;
  }

  return true;
}

char *readip_pcap(pcap_t *pd, unsigned int *len, long to_usec,
                  struct timeval *rcvdtime, struct link_header *linknfo, bool validate) {
  unsigned int offset = 0;
  struct pcap_pkthdr head;
  char *p;
  int datalink;
  int timedout = 0;
  struct timeval tv_start, tv_end;
  static char *alignedbuf = NULL;
  static unsigned int alignedbufsz = 0;
  static int warning = 0;

  if (linknfo) {
    memset(linknfo, 0, sizeof(*linknfo));
  }

  if (!pd)
    fatal("NULL packet device passed to %s", __func__);

  if (to_usec < 0) {
    if (!warning) {
      warning = 1;
      error("WARNING: Negative timeout value (%lu) passed to %s() -- using 0", to_usec, __func__);
    }
    to_usec = 0;
  }

  /* New packet capture device, need to recompute offset */
  if ((datalink = pcap_datalink(pd)) < 0)
    fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));

  /* NOTE: IF A NEW OFFSET EVER EXCEEDS THE CURRENT MAX (24), ADJUST
     MAX_LINK_HEADERSZ in libnetutil/netutil.h */
  switch (datalink) {
  case DLT_EN10MB:
    offset = 14;
    break;
  case DLT_IEEE802:
    offset = 22;
    break;
#ifdef __amigaos__
  case DLT_MIAMI:
    offset = 16;
    break;
#endif
#ifdef DLT_LOOP
  case DLT_LOOP:
#endif
  case DLT_NULL:
    offset = 4;
    break;
  case DLT_SLIP:
#ifdef DLT_SLIP_BSDOS
  case DLT_SLIP_BSDOS:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
    offset = 16;
#else
    offset = 24; /* Anyone use this??? */
#endif
    break;
  case DLT_PPP:
#ifdef DLT_PPP_BSDOS
  case DLT_PPP_BSDOS:
#endif
#ifdef DLT_PPP_SERIAL
  case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
  case DLT_PPP_ETHER:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
    offset = 4;
#else
#ifdef SOLARIS
    offset = 8;
#else
    offset = 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
    break;
  case DLT_RAW:
    offset = 0;
    break;
  case DLT_FDDI:
    offset = 21;
    break;
#ifdef DLT_ENC
  case DLT_ENC:
    offset = 12;
    break;
#endif /* DLT_ENC */
#ifdef DLT_LINUX_SLL
  case DLT_LINUX_SLL:
    offset = 16;
    break;
#endif
#ifdef DLT_IPNET
  case DLT_IPNET:
    offset = 24;
    break;
#endif
  default:
    p = (char *) pcap_next(pd, &head);
    if (head.caplen == 0) {
      /* Lets sleep a brief time and try again to increase the chance of seeing
         a real packet ... */
      usleep(500000);
      p = (char *) pcap_next(pd, &head);
    }
    if (head.caplen > 100000) {
      fatal("FATAL: %s: bogus caplen from libpcap (%d) on interface type %d", __func__, head.caplen, datalink);
    }
    error("FATAL:  Unknown datalink type (%d). Caplen: %d; Packet:", datalink, head.caplen);
    nmap_hexdump((unsigned char *) p, head.caplen);
    exit(1);
  }

  if (to_usec > 0) {
    gettimeofday(&tv_start, NULL);
  }

  do {

    p = NULL;
    /* It may be that protecting this with !pcap_selectable_fd_one_to_one is not
       necessary, that it is always safe to do a nonblocking read in this way on
       all platforms. But I have only tested it on Solaris. */
    if (!pcap_selectable_fd_one_to_one()) {
      int rc, nonblock;

      nonblock = pcap_getnonblock(pd, NULL);
      assert(nonblock == 0);
      rc = pcap_setnonblock(pd, 1, NULL);
      assert(rc == 0);
      p = (char *) pcap_next(pd, &head);
      rc = pcap_setnonblock(pd, nonblock, NULL);
      assert(rc == 0);
    }

    if (p == NULL) {
      /* Nonblocking pcap_next didn't get anything. */
      if (pcap_select(pd, to_usec) == 0)
        timedout = 1;
      else
        p = (char *) pcap_next(pd, &head);
    }

    if (p) {
      if (head.caplen <= offset) {
        *len = 0;
        return NULL;
      }
      if (offset && linknfo) {
        linknfo->datalinktype = datalink;
        linknfo->headerlen = offset;
        assert(offset <= MAX_LINK_HEADERSZ);
        memcpy(linknfo->header, p, MIN(sizeof(linknfo->header), offset));
      }
      p += offset;
    }
    if (!p) {
      /* Should we timeout? */
      if (to_usec == 0) {
        timedout = 1;
      } else if (to_usec > 0) {
        gettimeofday(&tv_end, NULL);
        if (TIMEVAL_SUBTRACT(tv_end, tv_start) >= to_usec) {
          timedout = 1;
        }
      }
    }
  } while (!timedout && (!p));

  if (timedout) {
    *len = 0;
    return NULL;
  }
  *len = head.caplen - offset;
  if (*len > alignedbufsz) {
    alignedbuf = (char *) safe_realloc(alignedbuf, *len);
    alignedbufsz = *len;
  }
  memcpy(alignedbuf, p, *len);

  if (validate) {
    /* Let's see if this packet passes inspection.. */
    if (!validatepkt((u8 *) alignedbuf, len)) {
      *len = 0;
      return NULL;
    }
  }
  // printf("Just got a packet at %li,%li\n", head.ts.tv_sec, head.ts.tv_usec);
  if (rcvdtime) {
    // FIXME: I eventually need to figure out why Windows head.ts time is sometimes BEFORE the time I
    // sent the packet (which is according to gettimeofday() in nbase).  For now, I will sadly have to
    // use gettimeofday() for Windows in this case
    // Actually I now allow .05 discrepancy.   So maybe this isn't needed.  I'll comment out for now.
    // Nope: it is still needed at least for Windows.  Sometimes the time from he pcap header is a
    // COUPLE SECONDS before the gettimeofday() results :(.
#if defined(WIN32) || defined(__amigaos__)
    gettimeofday(&tv_end, NULL);
    *rcvdtime = tv_end;
#else
    rcvdtime->tv_sec = head.ts.tv_sec;
    rcvdtime->tv_usec = head.ts.tv_usec;
    assert(head.ts.tv_sec);
#endif
  }

  if (rcvdtime)
    PacketTrace::trace(PacketTrace::RCVD, (u8 *) alignedbuf, *len,
                       rcvdtime);
  else
    PacketTrace::trace(PacketTrace::RCVD, (u8 *) alignedbuf, *len);

  return alignedbuf;
}

/* This function tries to determine the target's ethernet MAC address
   from a received packet as follows:
   1) If linkhdr is an ethernet header, grab the src mac (otherwise give up)
   2) If overwrite is 0 and a MAC is already set for this target, give up.
   3) If the packet source address is not the target, give up.
   4) Use the routing table to try to determine rather target is
      directly connected to the src host running Nmap.  If it is, set the MAC.

   This function returns 0 if it ends up setting the MAC, nonzero otherwise. */
int setTargetMACIfAvailable(Target *target, struct link_header *linkhdr,
                            const struct sockaddr_storage *src, int overwrite) {
  struct sockaddr_storage addr;
  size_t addr_len;

  if (!linkhdr || !target || !src)
    return 1;

  if (linkhdr->datalinktype != DLT_EN10MB || linkhdr->headerlen != 14)
    return 2;

  if (!overwrite && target->MACAddress())
    return 3;

  addr_len = sizeof(addr);
  target->TargetSockAddr(&addr, &addr_len);
  if (sockaddr_storage_cmp(src, &addr) != 0)
    return 4;

  /* Sometimes bogus MAC address still gets through, like during some localhost scans */
  if (memcmp(linkhdr->header + 6, "\0\0\0\0\0\0", 6) == 0)
    return 5;

  if (target->ifType() == devt_ethernet && target->directlyConnected()) {
    /* Yay!  This MAC address seems valid */
    target->setMACAddress(linkhdr->header + 6);
    return 0;
  }

  return 5;
}

/* This function ensures that the next hop MAC address for a target is
   filled in.  This address is the target's own MAC if it is directly
   connected, and the next hop mac otherwise.  Returns true if the
   address is set when the function ends, false if not.  This function
   firt checks if it is already set, if not it tries the arp cache,
   and if that fails it sends an ARP request itself.  This should be
   called after an ARP scan if many directly connected machines are
   involved. setDirectlyConnected() (whether true or false) should
   have already been called on target before this.  The target device
   and src mac address should also already be set.  */
bool setTargetNextHopMAC(Target *target) {
  struct sockaddr_storage targetss;
  size_t sslen;
  u8 mac[6];

  if (target->ifType() != devt_ethernet)
    return false; /* Duh. */

  /* First check if we already have it, duh. */
  if (target->NextHopMACAddress())
    return true;

  /* For connected machines, it is the same as the target addy */
  if (target->directlyConnected() && target->MACAddress()) {
    target->setNextHopMACAddress(target->MACAddress());
    return true;
  }

  if (target->directlyConnected()) {
    target->TargetSockAddr(&targetss, &sslen);
  } else {
    if (!target->nextHop(&targetss, &sslen))
      fatal("%s: Failed to determine nextHop to target", __func__);
  }

  if (getNextHopMAC(target->deviceFullName(), target->SrcMACAddress(), target->SourceSockAddr(), &targetss, mac)) {
    target->setNextHopMACAddress(mac);
    return true;
  }

  /* I'm afraid that we couldn't find it!  Maybe it doesn't exist? */
  return false;
}

/* Like to getTargetNextHopMAC(), but for arbitrary hosts (not Targets) */
bool getNextHopMAC(const char *iface, const u8 *srcmac, const struct sockaddr_storage *srcss,
                   const struct sockaddr_storage *dstss, u8 *dstmac) {
  arp_t *a;
  struct arp_entry ae;

  /* First, let us check the Nmap arp cache ... */
  if (mac_cache_get(dstss, dstmac))
    return true;

  /* Maybe the system ARP cache will be more helpful */
  a = arp_open();
  addr_ston((sockaddr *) dstss, &ae.arp_pa);
  if (arp_get(a, &ae) == 0) {
    mac_cache_set(dstss, ae.arp_ha.addr_eth.data);
    memcpy(dstmac, ae.arp_ha.addr_eth.data, 6);
    arp_close(a);
    return true;
  }
  arp_close(a);

  /* OK, the last choice is to send our own damn ARP request (and
     retransmissions if necessary) to determine the MAC */
  if (dstss->ss_family == AF_INET) {
    if (doArp(iface, srcmac, srcss, dstss, dstmac, PacketTrace::traceArp)) {
      mac_cache_set(dstss, dstmac);
      return true;
    }
  } /*else if (dstss->ss_family == AF_INET6) {
    if (doND(iface, srcmac, srcss, dstss, dstmac, PacketTrace::traceND)) {
      mac_cache_set(dstss, dstmac);
      return true;
    }
  }*/
    //we do not need ipv6

  return false;
}

/* Read an IP packet using libpcap .  We return the packet and take
   a pcap descriptor and a pointer to the packet length (which we set
   in the function. If you want a maximum length returned, you
   should specify that in pcap_open_live() */
/* to_usec is the timeout period in microseconds -- use 0 to skip the
   test and -1 to block forever.  Note that we don't interrupt pcap, so
   low values (and 0) degenerate to the timeout specified
   in pcap_open_live() */
/* If rcvdtime is non-null and a packet is returned, rcvd will be
   filled with the time that packet was captured from the wire by
   pcap.  If linknfo is not NULL, linknfo->headerlen and
   linknfo->header will be filled with the appropriate values. */
/* Specifying true for validate will enable validity checks against the
   received IP packet.  See validatepkt() for a list of checks. */
char *readipv4_pcap(pcap_t *pd, unsigned int *len, long to_usec,
                    struct timeval *rcvdtime, struct link_header *linknfo,
                    bool validate) {
  char *buf;

  buf = readip_pcap(pd, len, to_usec, rcvdtime, linknfo, validate);
  if (buf != NULL) {
    struct ip *ip;

    ip = (struct ip *) buf;
    if (*len < 1 || ip->ip_v != 4)
      return NULL;
  }

  return buf;
}

/* A simple function I wrote to help in debugging, shows the important fields
   of a TCP packet*/
int readtcppacket(const u8 *packet, int readdata) {

  struct ip *ip = (struct ip *) packet;
  struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + sizeof(struct ip));
  const unsigned char *data = packet + sizeof(struct ip) + sizeof(struct tcp_hdr);
  int tot_len;
  struct in_addr bullshit, bullshit2;
  char sourcehost[16];
  int i;
  int realfrag = 0;

  if (!packet) {
    error("%s: packet is NULL!", __func__);
    return -1;
  }

  bullshit.s_addr = ip->ip_src.s_addr;
  bullshit2.s_addr = ip->ip_dst.s_addr;
  realfrag = htons(ntohs(ip->ip_off) & IP_OFFMASK);
  tot_len = htons(ip->ip_len);
  strncpy(sourcehost, inet_ntoa(bullshit), 16);
  i = 4 * (ntohs(ip->ip_hl) + ntohs(tcp->th_off));
  if (ip->ip_p == IPPROTO_TCP) {
    if (realfrag)
      // log_write(LOG_PLAIN, "Packet is fragmented, offset field: %u\n",
      //           realfrag);
      printf("Packet is fragmented, offset field: %u\n",
                realfrag);
    else {
      // log_write(LOG_PLAIN,
      //           "TCP packet: %s:%d -> %s:%d (total: %d bytes)\n",
      //           sourcehost, ntohs(tcp->th_sport), inet_ntoa(bullshit2),
      //           ntohs(tcp->th_dport), tot_len);
      // log_write(LOG_PLAIN, "Flags: ");
      printf("TCP packet: %s:%d -> %s:%d (total: %d bytes)\n",
                sourcehost, ntohs(tcp->th_sport), inet_ntoa(bullshit2),
                ntohs(tcp->th_dport), tot_len);
      printf("Flags: ");
      if (!tcp->th_flags)
        printf("(none)");
      if (tcp->th_flags & TH_RST)
        printf("RST ");
      if (tcp->th_flags & TH_SYN)
        // log_write(LOG_PLAIN, "SYN ");
    	printf("SYN ");
      if (tcp->th_flags & TH_ACK)
        // log_write(LOG_PLAIN, "ACK ");
    	printf("ACK ");
      if (tcp->th_flags & TH_PUSH)
        // log_write(LOG_PLAIN, "PSH ");
    	printf("PSH ");
      if (tcp->th_flags & TH_FIN)
        // log_write(LOG_PLAIN, "FIN ");
    	printf("FIN ");
      if (tcp->th_flags & TH_URG)
        // log_write(LOG_PLAIN, "URG ");
    	printf("URG ");
      // log_write(LOG_PLAIN, "\n");
    printf("\n");

      // log_write(LOG_PLAIN, "ipid: %hu ttl: %hhu ", ntohs(ip->ip_id),
      //           ip->ip_ttl);
    printf("ipid: %hu ttl: %hhu ", ntohs(ip->ip_id),
                ip->ip_ttl);

      if (tcp->th_flags & (TH_SYN | TH_ACK))
        // log_write(LOG_PLAIN, "Seq: %u\tAck: %u\n",
        //           (unsigned int) ntohl(tcp->th_seq),
        //           (unsigned int) ntohl(tcp->th_ack));
    	printf("Seq: %u\tAck: %u\n",
                  (unsigned int) ntohl(tcp->th_seq),
                  (unsigned int) ntohl(tcp->th_ack));
      else if (tcp->th_flags & TH_SYN)
        // log_write(LOG_PLAIN, "Seq: %u\n",
        //           (unsigned int) ntohl(tcp->th_seq));
    	printf("Seq: %u\n",
                  (unsigned int) ntohl(tcp->th_seq));
      else if (tcp->th_flags & TH_ACK)
        // log_write(LOG_PLAIN, "Ack: %u\n",
        //           (unsigned int) ntohl(tcp->th_ack));
    	printf("Ack: %u\n",
                  (unsigned int) ntohl(tcp->th_ack));
    }
  }
  if (readdata && i < tot_len) {
    // log_write(LOG_PLAIN, "Data portion:\n");
    printf("Data portion:\n");
    while (i < tot_len) {
      // log_write(LOG_PLAIN, "%2X%c", data[i], ((i + 1) % 16) ? ' ' : '\n');
    	printf("%2X%c", data[i], ((i + 1) % 16) ? ' ' : '\n');
      i++;
    }
    // log_write(LOG_PLAIN, "\n");
    printf("\n");
  }

  return 0;
}

/* Examines the given tcp packet and obtains the TCP timestamp option
   information if available.  Note that the CALLER must ensure that
   "tcp" contains a valid header (in particular the th_off must be the
   true packet length and tcp must contain it).  If a valid timestamp
   option is found in the header, nonzero is returned and the
   'timestamp' and 'echots' parameters are filled in with the
   appropriate value (if non-null).  Otherwise 0 is returned and the
   parameters (if non-null) are filled with 0.  Remember that the
   correct way to check for errors is to look at the return value
   since a zero ts or echots could possibly be valid. */
int gettcpopt_ts(struct tcp_hdr *tcp, u32 *timestamp, u32 *echots) {

  unsigned char *p;
  int len = 0;
  int op;
  int oplen;

  /* first we find where the tcp options start ... */
  p = ((unsigned char *) tcp) + 20;
  len = 4 * tcp->th_off - 20;
  while (len > 0 && *p != 0 /* TCPOPT_EOL */ ) {
    op = *p++;
    if (op == 0 /* TCPOPT_EOL */ )
      break;
    if (op == 1 /* TCPOPT_NOP */ ) {
      len--;
      continue;
    }
    oplen = *p++;
    if (oplen < 2)
      break; /* No infinite loops, please */
    if (oplen > len)
      break; /* Not enough space */
    if (op == 8 /* TCPOPT_TIMESTAMP */  && oplen == 10) {
      /* Legitimate ts option */
      if (timestamp) {
        memcpy((char *) timestamp, p, 4);
        *timestamp = ntohl(*timestamp);
      }
      p += 4;
      if (echots) {
        memcpy((char *) echots, p, 4);
        *echots = ntohl(*echots);
      }
      return 1;
    }
    len -= oplen;
    p += oplen - 2;
  }

  /* Didn't find anything */
  if (timestamp)
    *timestamp = 0;
  if (echots)
    *echots = 0;
  return 0;
}

int send_tcp_raw_decoys(int sd, const struct eth_nfo *eth,
                        const struct in_addr *victim,
                        int ttl, bool df,
                        u8 *ipopt, int ipoptlen,
                        u16 sport, u16 dport,
                        u32 seq, u32 ack, u8 reserved, u8 flags,
                        u16 window, u16 urp, u8 *options, int optlen,
                        const char *data, u16 datalen) {
  int decoy;

  for (decoy = 0; decoy < o.numdecoys; decoy++)
    if (send_tcp_raw(sd, eth,
                     &((struct sockaddr_in *)&o.decoys[decoy])->sin_addr, victim,
                     ttl, df,
                     ipopt, ipoptlen,
                     sport, dport,
                     seq, ack, reserved, flags, window, urp,
                     options, optlen, data, datalen) == -1)
      return -1;

  return 0;
}

/* You need to call sethdrinclude(sd) on the sending sd before calling this */
int send_tcp_raw(int sd, const struct eth_nfo *eth,
                 const struct in_addr *source,
                 const struct in_addr *victim, int ttl, bool df,
                 u8 *ipops, int ipoptlen, u16 sport, u16 dport, u32 seq,
                 u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
                 u8 *options, int optlen, const char *data, u16 datalen) {
  struct sockaddr_storage dst;
  struct sockaddr_in *dst_in;
  unsigned int packetlen;
  int res = -1;

  u8 *packet = build_tcp_raw(source, victim,
                             ttl, get_random_u16(), IP_TOS_DEFAULT, df,
                             ipops, ipoptlen,
                             sport, dport,
                             seq, ack, reserved, flags, window, urp,
                             options, optlen,
                             data, datalen, &packetlen);
  if (!packet)
    return -1;
  memset(&dst, 0, sizeof(dst));
  dst_in = (struct sockaddr_in *) &dst;
  dst_in->sin_family = AF_INET;
  dst_in->sin_addr = *victim;
  res = send_ip_packet(sd, eth, &dst, packet, packetlen);

  free(packet);
  return res;
}