#ifndef MY_TCPIP_H
#define MY_TCPIP_H
#include "netutil.h"
#include "target.h"
#include <netdb.h>

/* Tries to resolve the given name (or literal IP) into a sockaddr
   structure. This function calls getaddrinfo and returns the same
   addrinfo linked list that getaddrinfo produces. Returns NULL for any
   error or failure to resolve. */
struct addrinfo *resolve_all(const char *hostname, int pf);

/* Takes a destination address (dst) and tries to determine the
   source address and interface necessary to route to this address.
   If no route is found, false is returned and rnfo is undefined.  If
   a route is found, true is returned and rnfo is filled in with all
   of the routing details.  This function takes into account -S and -e
   options set by user (o.spoofsource, o.device) */
int nmap_route_dst(const struct sockaddr_storage *dst, struct route_nfo *rnfo);

int nmap_raw_socket();

/* Give broadcast permission to a socket */
void broadcast_socket(int sd);

// Returns whether the packet receive time value obtained from libpcap
// (and thus by readip_pcap()) should be considered valid.  When
// invalid (Windows and Amiga), readip_pcap returns the time you called it.
bool pcap_recv_timeval_valid();

/* Converts an IP address given in a sockaddr_storage to an IPv4 or
   IPv6 IP address string.  Since a static buffer is returned, this is
   not thread-safe and can only be used once in calls like printf()
*/
const char *inet_socktop(struct sockaddr_storage *ss);

/* Used for tracing all packets sent or received (eg the
   --packet-trace option) */

class PacketTrace {
 public:
  static const int SENT=1; /* These two values must not be changed */
  static const int RCVD=2;
  typedef int pdirection;
  /* Takes an IP PACKET and prints it if packet tracing is enabled.
     'packet' must point to the IPv4 header. The direction must be
     PacketTrace::SENT or PacketTrace::RCVD .  Optional 'now' argument
     makes this function slightly more efficient by avoiding a gettimeofday()
     call. */
  static void trace(pdirection pdir, const u8 *packet, u32 len,
                    struct timeval *now=NULL);
/* Adds a trace entry when a connect() is attempted if packet tracing
   is enabled.  Pass IPPROTO_TCP or IPPROTO_UDP as the protocol.  The
   sock may be a sockaddr_in or sockaddr_in6.  The return code of
   connect is passed in connectrc.  If the return code is -1, get the
   errno and pass that as connect_errno. */
  static void traceConnect(u8 proto, const struct sockaddr *sock,
                           int socklen, int connectrc, int connect_errno,
                           const struct timeval *now);
  /* Takes an ARP PACKET (including ethernet header) and prints it if
     packet tracing is enabled.  'frame' must point to the 14-byte
     ethernet header (e.g. starting with destination addr). The
     direction must be PacketTrace::SENT or PacketTrace::RCVD .
     Optional 'now' argument makes this function slightly more
     efficient by avoiding a gettimeofday() call. */
  static void traceArp(pdirection pdir, const u8 *frame, u32 len,
                                    struct timeval *now);
  static void traceND(pdirection pdir, const u8 *frame, u32 len,
                                    struct timeval *now);
};

/* Builds a TCP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_tcp_raw(const struct in_addr *source, const struct in_addr *victim,
                  int ttl, u16 ipid, u8 tos, bool df,
                  const u8* ipopt, int ipoptlen,
                  u16 sport, u16 dport,
                  u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
                  const u8 *options, int optlen,
                  const char *data, u16 datalen,
                  u32 *packetlen);

/* Builds an IP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_ip_raw(const struct in_addr *source, const struct in_addr *victim,
                 u8 proto,
                 int ttl, u16 ipid, u8 tos, bool df,
                 const u8* ipopt, int ipoptlen,
                 const char *data, u16 datalen,
                 u32 *packetlen);

/* Send a pre-built IPv4 or IPv6 packet */
int send_ip_packet(int sd, const struct eth_nfo *eth,
  const struct sockaddr_storage *dst,
  const u8 *packet, unsigned int packetlen);

class PacketCounter {
 public:
  PacketCounter() : sendPackets(0), sendBytes(0), recvPackets(0), recvBytes(0) {}
#if WIN32
  unsigned __int64
#else
  unsigned long long
#endif
          sendPackets, sendBytes, recvPackets, recvBytes;
};

/* Builds a UDP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_udp_raw(const struct in_addr *source, const struct in_addr *victim,
       int ttl, u16 ipid, u8 tos, bool df,
                  u8* ipopt, int ipoptlen,
       u16 sport, u16 dport,
       const char *data, u16 datalen,
       u32 *packetlen);

/* Builds an SCTP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_sctp_raw(const struct in_addr *source, const struct in_addr *victim,
                   int ttl, u16 ipid, u8 tos, bool df,
                   u8* ipopt, int ipoptlen,
                   u16 sport, u16 dport,
                   u32 vtag, char *chunks, int chunkslen,
                   const char *data, u16 datalen,
                   u32 *packetlen);

/* Builds an ICMP packet (including an IP header) by packing the
   fields with the given information.  It allocates a new buffer to
   store the packet contents, and then returns that buffer.  The
   packet is not actually sent by this function.  Caller must delete
   the buffer when finished with the packet.  The packet length is
   returned in packetlen, which must be a valid int pointer. The
   id/seq will be converted to network byte order (if it differs from
   HBO) */
u8 *build_icmp_raw(const struct in_addr *source, const struct in_addr *victim,
                   int ttl, u16 ipid, u8 tos, bool df,
                   u8* ipopt, int ipoptlen,
                   u16 seq, unsigned short id, u8 ptype, u8 pcode,
                   const char *data, u16 datalen, u32 *packetlen);

unsigned short in_cksum(u16 *ptr,int nbytes);

/* Builds an IGMP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in packetlen,
   which must be a valid int pointer.
 */
u8 *build_igmp_raw(const struct in_addr *source, const struct in_addr *victim,
                   int ttl, u16 ipid, u8 tos, bool df,
                   u8* ipopt, int ipoptlen,
                   u8 ptype, u8 pcode,
                   const char *data, u16 datalen, u32 *packetlen);

char *readip_pcap(pcap_t *pd, unsigned int *len, long to_usec,
                  struct timeval *rcvdtime, struct link_header *linknfo, bool validate);

/* This function tries to determine the target's ethernet MAC address
   from a received packet as follows:
   1) If linkhdr is an ethernet header, grab the src mac (otherwise give up)
   2) If overwrite is 0 and a MAC is already set for this target, give up.
   3) If the packet source address is not the target, give up.
   4) Use the routing table to try to determine rather target is
      directly connected to the src host running Nmap.  If it is, set the MAC.

   This function returns 0 if it ends up setting the MAC, nonzero otherwise
*/

int setTargetMACIfAvailable(Target *target, struct link_header *linkhdr,
                            const struct sockaddr_storage *src, int overwrite);


/* This function ensures that the next hop MAC address for a target is
   filled in.  This address is the target's own MAC if it is directly
   connected, and the next hop mac otherwise.  Returns true if the
   address is set when the function ends, false if not.  This function
   firt checks if it is already set, if not it tries the arp cache,
   and if that fails it sends an ARP request itself.  This should be called
   after an ARP scan if many directly connected machines are involved. */
bool setTargetNextHopMAC(Target *target);

bool getNextHopMAC(const char *iface, const u8 *srcmac, const struct sockaddr_storage *srcss,
                   const struct sockaddr_storage *dstss, u8 *dstmac);

/* If rcvdtime is non-null and a packet is returned, rcvd will be
   filled with the time that packet was captured from the wire by
   pcap.  If linknfo is not NULL, lnkinfo->headerlen and
   lnkinfo->header will be filled with the appropriate values. */
char *readipv4_pcap(pcap_t *pd, unsigned int *len, long to_usec,
                    struct timeval *rcvdtime, struct link_header *linknfo, bool validate);
/* A simple function I wrote to help in debugging, shows the important fields
   of a TCP packet*/
int readtcppacket(const u8 *packet, int readdata);

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
int gettcpopt_ts(struct tcp_hdr *tcp, u32 *timestamp, u32 *echots);

int send_tcp_raw_decoys(int sd, const struct eth_nfo *eth,
                         const struct in_addr *victim,
                         int ttl, bool df,
                         u8* ipopt, int ipoptlen,
                         u16 sport, u16 dport,
                         u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
                         u8 *options, int optlen,
                         const char *data, u16 datalen);

/* Build and send a raw tcp packet.  If TTL is -1, a partially random
   (but likely large enough) one is chosen */
int send_tcp_raw(int sd, const struct eth_nfo *eth,
                  const struct in_addr *source, const struct in_addr *victim,
                  int ttl, bool df,
                  u8* ipopt, int ipoptlen,
                  u16 sport, u16 dport,
                  u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
                  u8 *options, int optlen,
                  const char *data, u16 datalen);

#endif