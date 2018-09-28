#ifndef SCAN_LISTS_H
#define SCAN_LISTS_H

/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
        /* The "synprobes" are also used when doing a connect() ping */
        unsigned short *syn_ping_ports;
        unsigned short *ack_ping_ports;
        unsigned short *udp_ping_ports;
        unsigned short *sctp_ping_ports;
        unsigned short *proto_ping_ports;
        int syn_ping_count;
        int ack_ping_count;
        int udp_ping_count;
        int sctp_ping_count;
        int proto_ping_count;
        //the above fields are only used for host discovery
        //the fields below are only used for port scanning
        unsigned short *tcp_ports;
        int tcp_count;
        unsigned short *udp_ports;
        int udp_count;
        unsigned short *sctp_ports;
        int sctp_count;
        unsigned short *prots;
        int prot_count;
};

typedef enum {
  STYPE_UNKNOWN,
  HOST_DISCOVERY,
  ACK_SCAN,
  SYN_SCAN,
  FIN_SCAN,
  XMAS_SCAN,
  UDP_SCAN,
  CONNECT_SCAN,
  NULL_SCAN,
  WINDOW_SCAN,
  SCTP_INIT_SCAN,
  SCTP_COOKIE_ECHO_SCAN,
  MAIMON_SCAN,
  IPPROT_SCAN,
  PING_SCAN,
  PING_SCAN_ARP,
  IDLE_SCAN,
  BOUNCE_SCAN,
  SERVICE_SCAN,
  OS_SCAN,
  SCRIPT_PRE_SCAN,
  SCRIPT_SCAN,
  SCRIPT_POST_SCAN,
  TRACEROUTE,
  PING_SCAN_ND
} stype;

/* general helper functions */
const char *scantype2str(stype scantype);

/* port manipulators */
void getpts(const char *expr, struct scan_lists * ports); /* someone stole the name getports()! */

void getpts_simple(const char *origexpr, int range_type,
                   unsigned short **list, int *count);

void removepts(const char *expr, struct scan_lists * ports);

void free_scan_lists(struct scan_lists *ports);

#endif