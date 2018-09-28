#ifndef MY_IP_H
#define MY_IP_H
//it is also borrowed from libdnet
#include "addr.h"

#define IP_ADDR_LEN	4		/* IP address length */
#define IP_ADDR_BITS	32		/* IP address bits */

/*
 * Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
 */
#define IP_TOS_DEFAULT		0x00	/* default */
#define IP_TOS_LOWDELAY		0x10	/* low delay */
#define IP_TOS_THROUGHPUT	0x08	/* high throughput */
#define IP_TOS_RELIABILITY	0x04	/* high reliability */
#define IP_TOS_LOWCOST		0x02	/* low monetary cost - XXX */
#define IP_TOS_ECT		0x02	/* ECN-capable transport */
#define IP_TOS_CE		0x01	/* congestion experienced */

/*
 * Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
 */
#define	IP_PROTO_IP		0		/* dummy for IP */
#define IP_PROTO_HOPOPTS	IP_PROTO_IP	/* IPv6 hop-by-hop options */
#define	IP_PROTO_ICMP		1		/* ICMP */
#define	IP_PROTO_IGMP		2		/* IGMP */
#define IP_PROTO_GGP		3		/* gateway-gateway protocol */
#define	IP_PROTO_IPIP		4		/* IP in IP */
#define IP_PROTO_ST		5		/* ST datagram mode */
#define	IP_PROTO_TCP		6		/* TCP */
#define IP_PROTO_CBT		7		/* CBT */
#define	IP_PROTO_EGP		8		/* exterior gateway protocol */
#define IP_PROTO_IGP		9		/* interior gateway protocol */
#define IP_PROTO_BBNRCC		10		/* BBN RCC monitoring */
#define IP_PROTO_NVP		11		/* Network Voice Protocol */
#define	IP_PROTO_PUP		12		/* PARC universal packet */
#define IP_PROTO_ARGUS		13		/* ARGUS */
#define IP_PROTO_EMCON		14		/* EMCON */
#define IP_PROTO_XNET		15		/* Cross Net Debugger */
#define IP_PROTO_CHAOS		16		/* Chaos */
#define	IP_PROTO_UDP		17		/* UDP */
#define IP_PROTO_MUX		18		/* multiplexing */
#define IP_PROTO_DCNMEAS	19		/* DCN measurement */
#define IP_PROTO_HMP		20		/* Host Monitoring Protocol */
#define IP_PROTO_PRM		21		/* Packet Radio Measurement */
#define	IP_PROTO_IDP		22		/* Xerox NS IDP */
#define IP_PROTO_TRUNK1		23		/* Trunk-1 */
#define IP_PROTO_TRUNK2		24		/* Trunk-2 */
#define IP_PROTO_LEAF1		25		/* Leaf-1 */
#define IP_PROTO_LEAF2		26		/* Leaf-2 */
#define IP_PROTO_RDP		27		/* "Reliable Datagram" proto */
#define IP_PROTO_IRTP		28		/* Inet Reliable Transaction */
#define	IP_PROTO_TP		29 		/* ISO TP class 4 */
#define IP_PROTO_NETBLT		30		/* Bulk Data Transfer */
#define IP_PROTO_MFPNSP		31		/* MFE Network Services */
#define IP_PROTO_MERITINP	32		/* Merit Internodal Protocol */
#define IP_PROTO_SEP		33		/* Sequential Exchange proto */
#define IP_PROTO_3PC		34		/* Third Party Connect proto */
#define IP_PROTO_IDPR		35		/* Interdomain Policy Route */
#define IP_PROTO_XTP		36		/* Xpress Transfer Protocol */
#define IP_PROTO_DDP		37		/* Datagram Delivery Proto */
#define IP_PROTO_CMTP		38		/* IDPR Ctrl Message Trans */
#define IP_PROTO_TPPP		39		/* TP++ Transport Protocol */
#define IP_PROTO_IL		40		/* IL Transport Protocol */
#define IP_PROTO_IPV6		41		/* IPv6 */
#define IP_PROTO_SDRP		42		/* Source Demand Routing */
#define IP_PROTO_ROUTING	43		/* IPv6 routing header */
#define IP_PROTO_FRAGMENT	44		/* IPv6 fragmentation header */
#define IP_PROTO_RSVP		46		/* Reservation protocol */
#define	IP_PROTO_GRE		47		/* General Routing Encap */
#define IP_PROTO_MHRP		48		/* Mobile Host Routing */
#define IP_PROTO_ENA		49		/* ENA */
#define	IP_PROTO_ESP		50		/* Encap Security Payload */
#define	IP_PROTO_AH		51		/* Authentication Header */
#define IP_PROTO_INLSP		52		/* Integated Net Layer Sec */
#define IP_PROTO_SWIPE		53		/* SWIPE */
#define IP_PROTO_NARP		54		/* NBMA Address Resolution */
#define	IP_PROTO_MOBILE		55		/* Mobile IP, RFC 2004 */
#define IP_PROTO_TLSP		56		/* Transport Layer Security */
#define IP_PROTO_SKIP		57		/* SKIP */
#define IP_PROTO_ICMPV6		58		/* ICMP for IPv6 */
#define IP_PROTO_NONE		59		/* IPv6 no next header */
#define IP_PROTO_DSTOPTS	60		/* IPv6 destination options */
#define IP_PROTO_ANYHOST	61		/* any host internal proto */
#define IP_PROTO_CFTP		62		/* CFTP */
#define IP_PROTO_ANYNET		63		/* any local network */
#define IP_PROTO_EXPAK		64		/* SATNET and Backroom EXPAK */
#define IP_PROTO_KRYPTOLAN	65		/* Kryptolan */
#define IP_PROTO_RVD		66		/* MIT Remote Virtual Disk */
#define IP_PROTO_IPPC		67		/* Inet Pluribus Packet Core */
#define IP_PROTO_DISTFS		68		/* any distributed fs */
#define IP_PROTO_SATMON		69		/* SATNET Monitoring */
#define IP_PROTO_VISA		70		/* VISA Protocol */
#define IP_PROTO_IPCV		71		/* Inet Packet Core Utility */
#define IP_PROTO_CPNX		72		/* Comp Proto Net Executive */
#define IP_PROTO_CPHB		73		/* Comp Protocol Heart Beat */
#define IP_PROTO_WSN		74		/* Wang Span Network */
#define IP_PROTO_PVP		75		/* Packet Video Protocol */
#define IP_PROTO_BRSATMON	76		/* Backroom SATNET Monitor */
#define IP_PROTO_SUNND		77		/* SUN ND Protocol */
#define IP_PROTO_WBMON		78		/* WIDEBAND Monitoring */
#define IP_PROTO_WBEXPAK	79		/* WIDEBAND EXPAK */
#define	IP_PROTO_EON		80		/* ISO CNLP */
#define IP_PROTO_VMTP		81		/* Versatile Msg Transport*/
#define IP_PROTO_SVMTP		82		/* Secure VMTP */
#define IP_PROTO_VINES		83		/* VINES */
#define IP_PROTO_TTP		84		/* TTP */
#define IP_PROTO_NSFIGP		85		/* NSFNET-IGP */
#define IP_PROTO_DGP		86		/* Dissimilar Gateway Proto */
#define IP_PROTO_TCF		87		/* TCF */
#define IP_PROTO_EIGRP		88		/* EIGRP */
#define IP_PROTO_OSPF		89		/* Open Shortest Path First */
#define IP_PROTO_SPRITERPC	90		/* Sprite RPC Protocol */
#define IP_PROTO_LARP		91		/* Locus Address Resolution */
#define IP_PROTO_MTP		92		/* Multicast Transport Proto */
#define IP_PROTO_AX25		93		/* AX.25 Frames */
#define IP_PROTO_IPIPENCAP	94		/* yet-another IP encap */
#define IP_PROTO_MICP		95		/* Mobile Internet Ctrl */
#define IP_PROTO_SCCSP		96		/* Semaphore Comm Sec Proto */
#define IP_PROTO_ETHERIP	97		/* Ethernet in IPv4 */
#define	IP_PROTO_ENCAP		98		/* encapsulation header */
#define IP_PROTO_ANYENC		99		/* private encryption scheme */
#define IP_PROTO_GMTP		100		/* GMTP */
#define IP_PROTO_IFMP		101		/* Ipsilon Flow Mgmt Proto */
#define IP_PROTO_PNNI		102		/* PNNI over IP */
#define IP_PROTO_PIM		103		/* Protocol Indep Multicast */
#define IP_PROTO_ARIS		104		/* ARIS */
#define IP_PROTO_SCPS		105		/* SCPS */
#define IP_PROTO_QNX		106		/* QNX */
#define IP_PROTO_AN		107		/* Active Networks */
#define IP_PROTO_IPCOMP		108		/* IP Payload Compression */
#define IP_PROTO_SNP		109		/* Sitara Networks Protocol */
#define IP_PROTO_COMPAQPEER	110		/* Compaq Peer Protocol */
#define IP_PROTO_IPXIP		111		/* IPX in IP */
#define IP_PROTO_VRRP		112		/* Virtual Router Redundancy */
#define IP_PROTO_PGM		113		/* PGM Reliable Transport */
#define IP_PROTO_ANY0HOP	114		/* 0-hop protocol */
#define IP_PROTO_L2TP		115		/* Layer 2 Tunneling Proto */
#define IP_PROTO_DDX		116		/* D-II Data Exchange (DDX) */
#define IP_PROTO_IATP		117		/* Interactive Agent Xfer */
#define IP_PROTO_STP		118		/* Schedule Transfer Proto */
#define IP_PROTO_SRP		119		/* SpectraLink Radio Proto */
#define IP_PROTO_UTI		120		/* UTI */
#define IP_PROTO_SMP		121		/* Simple Message Protocol */
#define IP_PROTO_SM		122		/* SM */
#define IP_PROTO_PTP		123		/* Performance Transparency */
#define IP_PROTO_ISIS		124		/* ISIS over IPv4 */
#define IP_PROTO_FIRE		125		/* FIRE */
#define IP_PROTO_CRTP		126		/* Combat Radio Transport */
#define IP_PROTO_CRUDP		127		/* Combat Radio UDP */
#define IP_PROTO_SSCOPMCE	128		/* SSCOPMCE */
#define IP_PROTO_IPLT		129		/* IPLT */
#define IP_PROTO_SPS		130		/* Secure Packet Shield */
#define IP_PROTO_PIPE		131		/* Private IP Encap in IP */
#define IP_PROTO_SCTP		132		/* Stream Ctrl Transmission */
#define IP_PROTO_FC		133		/* Fibre Channel */
#define IP_PROTO_RSVPIGN	134		/* RSVP-E2E-IGNORE */
#define	IP_PROTO_RAW		255		/* Raw IP packets */
#define IP_PROTO_RESERVED	IP_PROTO_RAW	/* Reserved */
#define	IP_PROTO_MAX		255


int	 ip_pton(const char *src, ip_addr_t *dst);

int	 ip_cksum_add(const void *buf, size_t len, int cksum);

#define	 ip_cksum_carry(x) \
	    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))


#endif