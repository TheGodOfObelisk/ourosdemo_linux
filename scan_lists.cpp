#include "scan_lists.h"
#include "base.h"
#include "services.h"
#include "scanops.h"
#include "errorhandle.h"
#include "protocols.h"
#include <assert.h>
#include <stdlib.h>

extern ScanOps o;

static void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int range_type,
                       int *portwarning, bool change_range_type = true);

/* Just a routine for obtaining a string for printing based on the scantype */
const char *scantype2str(stype scantype) {

  switch (scantype) {
  case STYPE_UNKNOWN:
    return "Unknown Scan Type";
    break;
  case HOST_DISCOVERY:
    return "Host Discovery";
    break;
  case ACK_SCAN:
    return "ACK Scan";
    break;
  case SYN_SCAN:
    return "SYN Stealth Scan";
    break;
  case FIN_SCAN:
    return "FIN Scan";
    break;
  case XMAS_SCAN:
    return "XMAS Scan";
    break;
  case UDP_SCAN:
    return "UDP Scan";
    break;
  case CONNECT_SCAN:
    return "Connect Scan";
    break;
  case NULL_SCAN:
    return "NULL Scan";
    break;
  case WINDOW_SCAN:
    return "Window Scan";
    break;
  case SCTP_INIT_SCAN:
    return "SCTP INIT Scan";
    break;
  case SCTP_COOKIE_ECHO_SCAN:
    return "SCTP COOKIE-ECHO Scan";
    break;
  case MAIMON_SCAN:
    return "Maimon Scan";
    break;
  case IPPROT_SCAN:
    return "IPProto Scan";
    break;
  case PING_SCAN:
    return "Ping Scan";
    break;
  case PING_SCAN_ARP:
    return "ARP Ping Scan";
    break;
  case PING_SCAN_ND:
    return "ND Ping Scan";
    break;
  case IDLE_SCAN:
    return "Idle Scan";
    break;
  case BOUNCE_SCAN:
    return "Bounce Scan";
    break;
  case SERVICE_SCAN:
    return "Service Scan";
    break;
  case OS_SCAN:
    return "OS Scan";
    break;
  case SCRIPT_PRE_SCAN:
    return "Script Pre-Scan";
    break;
  case SCRIPT_SCAN:
    return "Script Scan";
    break;
  case SCRIPT_POST_SCAN:
    return "Script Post-Scan";
    break;
  case TRACEROUTE:
    return "Traceroute" ;
    break;
  default:
    assert(0);
    break;
  }

  return NULL; /* Unreached */

}


void getpts(const char *origexpr, struct scan_lists *ports) {
  u8 *porttbl;
  int range_type = 0;
  int portwarning = 0;
  int i, tcpi, udpi, sctpi, proti;

  if (o.TCPScan())
    range_type |= SCAN_TCP_PORT;
  if (o.UDPScan())
    range_type |= SCAN_UDP_PORT;
  if (o.SCTPScan())
    range_type |= SCAN_SCTP_PORT;
  if (o.ipprotscan)
    range_type |= SCAN_PROTOCOLS;
  if (o.noportscan && o.exclude_portlist) { // We want to exclude from ping scans in this case but we take port list normally and then removepts() handles it
    range_type |= SCAN_TCP_PORT;
    range_type |= SCAN_UDP_PORT;
    range_type |= SCAN_SCTP_PORT;
  }

  porttbl = (u8 *) safe_zalloc(65536);

  getpts_aux(origexpr,      // Pass on the expression
             0,             // Don't start off nested
             porttbl,       // Our allocated port table
             range_type,    // Defaults to TCP/UDP/SCTP/Protos
             &portwarning); // No, we haven't warned them about dup ports yet

  ports->tcp_count = 0;
  ports->udp_count = 0;
  ports->sctp_count = 0;
  ports->prot_count = 0;
  for (i = 0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_count++;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_count++;
    if (porttbl[i] & SCAN_SCTP_PORT)
      ports->sctp_count++;
    if (porttbl[i] & SCAN_PROTOCOLS && i < 256)
      ports->prot_count++;
  }

  if (range_type != 0 && 0 == (ports->tcp_count + ports->udp_count + ports->sctp_count + ports->prot_count))
    fatal("No ports specified -- If you really don't want to scan any ports use ping scan...");

  if (ports->tcp_count) {
    ports->tcp_ports = (unsigned short *)safe_zalloc(ports->tcp_count * sizeof(unsigned short));
  }
  if (ports->udp_count) {
    ports->udp_ports = (unsigned short *)safe_zalloc(ports->udp_count * sizeof(unsigned short));
  }
  if (ports->sctp_count) {
    ports->sctp_ports = (unsigned short *)safe_zalloc(ports->sctp_count * sizeof(unsigned short));
  }
  if (ports->prot_count) {
    ports->prots = (unsigned short *)safe_zalloc(ports->prot_count * sizeof(unsigned short));
  }

  for (i = tcpi = udpi = sctpi = proti = 0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_ports[tcpi++] = i;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_ports[udpi++] = i;
    if (porttbl[i] & SCAN_SCTP_PORT)
      ports->sctp_ports[sctpi++] = i;
    if (porttbl[i] & SCAN_PROTOCOLS && i < 256)
      ports->prots[proti++] = i;
  }

  free(porttbl);
}

/* This function is like getpts except it only allocates space for and stores
  values into one unsigned short array, instead of an entire scan_lists struct
  For that reason, T:, U:, S: and P: restrictions are not allowed and only one
  bit in range_type may be set. */
void getpts_simple(const char *origexpr, int range_type,
                   unsigned short **list, int *count) {
  u8 *porttbl;
  int portwarning = 0;
  int i, j;

  /* Make sure that only one bit in range_type is set (or that range_type is 0,
     which is useless but not incorrect). */
  assert((range_type & (range_type - 1)) == 0);

  porttbl = (u8 *) safe_zalloc(65536);

  /* Get the ports but do not allow changing the type with T:, U:, or P:. */
  getpts_aux(origexpr, 0, porttbl, range_type, &portwarning, false);

  /* Count how many are set. */
  *count = 0;
  for (i = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*count)++;
  }

  if (*count == 0) {
    free(porttbl);
    return;
  }

  *list = (unsigned short *) safe_zalloc(*count * sizeof(unsigned short));

  /* Fill in the list. */
  for (i = 0, j = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*list)[j++] = i;
  }

  free(porttbl);
}

/* removepts() takes a port specification and removes any matching ports
  from the given scan_lists struct. */

static int remaining_ports(unsigned short int *ports, int count, unsigned short int *exclude_ports, int exclude_count, const char *type = "");

void removepts(const char *expr, struct scan_lists * ports) {
  static struct scan_lists exclude_ports;

  if (!expr)
    return;

  getpts(expr, &exclude_ports);

  #define SUBTRACT_PORTS(type,excludetype) \
    ports->type##_count = remaining_ports(ports->type##_ports, \
                                          ports->type##_count, \
                                          exclude_ports.excludetype##_ports, \
                                          exclude_ports.excludetype##_count, \
                                          #type)

  SUBTRACT_PORTS(tcp, tcp);
  SUBTRACT_PORTS(udp, udp);
  SUBTRACT_PORTS(sctp, sctp);
  SUBTRACT_PORTS(syn_ping, tcp);
  SUBTRACT_PORTS(ack_ping, tcp);
  SUBTRACT_PORTS(udp_ping, udp);
  SUBTRACT_PORTS(sctp_ping, sctp);

  #define prot_ports prots
  SUBTRACT_PORTS(prot, prot);
  SUBTRACT_PORTS(proto_ping, prot);
  #undef prot_ports

  #undef SUBTRACT_PORTS

  free_scan_lists(&exclude_ports);
}

void free_scan_lists(struct scan_lists *ports) {
  if (ports->tcp_ports)
    free(ports->tcp_ports);
  if (ports->udp_ports)
    free(ports->udp_ports);
  if (ports->sctp_ports)
    free(ports->sctp_ports);
  if (ports->prots)
    free(ports->prots);
  if (ports->syn_ping_ports)
    free(ports->syn_ping_ports);
  if (ports->ack_ping_ports)
    free(ports->ack_ping_ports);
  if (ports->udp_ping_ports)
    free(ports->udp_ping_ports);
  if (ports->proto_ping_ports)
    free(ports->proto_ping_ports);
}

/* getpts() and getpts_simple() (see above) are wrappers for this function */

static void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int range_type, int *portwarning, bool change_range_type) {
  long rangestart = -2343242, rangeend = -9324423;
  const char *current_range;
  char *endptr;
  char servmask[128];  // A protocol name can be up to 127 chars + nul byte
  int i;

  /* An example of proper syntax to use in error messages. */
  const char *syntax_example;
  if (change_range_type)
    syntax_example = "-100,200-1024,T:3000-4000,U:60000-";
  else
    syntax_example = "-100,200-1024,3000-4000,60000-";

  current_range = origexpr;
  do {
    while (isspace((int) (unsigned char) *current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */

    if (change_range_type) {
      if (*current_range == 'T' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_TCP_PORT;
        continue;
      }
      if (*current_range == 'U' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_UDP_PORT;
        continue;
      }
      if (*current_range == 'S' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_SCTP_PORT;
        continue;
      }
      if (*current_range == 'P' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_PROTOCOLS;
        continue;
      }
    }

    if (*current_range == '[') {
      if (nested)
        fatal("Can't nest [] brackets in port/protocol specification");

      getpts_aux(++current_range, 1, porttbl, range_type, portwarning);

      // Skip past the ']'. This is OK because we can't nest []s
      while (*current_range != ']' && *current_range != '\0')
        current_range++;
      if (*current_range == ']')
        current_range++;

      // Skip over a following ',' so we're ready to keep parsing
      if (*current_range == ',')
        current_range++;

      continue;
    } else if (*current_range == ']') {
      if (!nested)
        fatal("Unexpected ] character in port/protocol specification");

      return;
    } else if (*current_range == '-') {
      if (range_type & SCAN_PROTOCOLS)
        rangestart = 0;
      else
        rangestart = 1;
    } else if (isdigit((int) (unsigned char) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (range_type & SCAN_PROTOCOLS) {
        if (rangestart < 0 || rangestart > 255)
          fatal("Protocols specified must be between 0 and 255 inclusive");
      } else {
        if (rangestart < 0 || rangestart > 65535)
          fatal("Ports specified must be between 0 and 65535 inclusive");
      }
      current_range = endptr;
      while (isspace((int) (unsigned char) *current_range)) current_range++;
    } else if (islower((int) (unsigned char) *current_range) || *current_range == '*' || *current_range == '?') {
      i = 0;

      while (*current_range && !isspace((int) (unsigned char) *current_range) && *current_range != ',' && *current_range != ']') {
        servmask[i++] = *(current_range++);
        if (i >= ((int)sizeof(servmask) - 1))
          fatal("A service mask in the port/protocol specification is either malformed or too long");
      }

      if (*current_range && *current_range != ']') current_range++; // We want the '] character to be picked up on the next pass
      servmask[i] = '\0'; // Finish the string

      i = addportsfromservmask(servmask, porttbl, range_type);
      if (range_type & SCAN_PROTOCOLS)
        i += addprotocolsfromservmask(servmask, porttbl);

      if (i == 0)
        fatal("Found no matches for the service mask '%s' and your specified protocols", servmask);

      continue;

    } else {
      fatal("Error #485: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    /* Now I have a rangestart, time to go after rangeend */
    if (!*current_range || *current_range == ',' || *current_range == ']') {
      /* Single port specification */
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (!*current_range || *current_range == ',' || *current_range == ']') {
        /* Ended with a -, meaning up until the last possible port */
        if (range_type & SCAN_PROTOCOLS)
          rangeend = 255;
        else
          rangeend = 65535;
      } else if (isdigit((int) (unsigned char) *current_range)) {
        rangeend = strtol(current_range, &endptr, 10);
        if (range_type & SCAN_PROTOCOLS) {
          if (rangeend < 0 || rangeend > 255)
            fatal("Protocols specified must be between 0 and 255 inclusive");
        } else {
          if (rangeend < 0 || rangeend > 65535)
            fatal("Ports specified must be between 0 and 65535 inclusive");
        }
        current_range = endptr;
      } else {
        fatal("Error #486: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
      }
      if (rangeend < rangestart) {
        fatal("Your %s range %ld-%ld is backwards. Did you mean %ld-%ld?",
              (range_type & SCAN_PROTOCOLS) ? "protocol" : "port",
              rangestart, rangeend, rangeend, rangestart);
      }
    } else {
      fatal("Error #487: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while (rangestart <= rangeend) {
      if (porttbl[rangestart] & range_type) {
        if (!(*portwarning)) {
          error("WARNING: Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
          (*portwarning)++;
        }
      } else {
        if (nested) {
          if ((range_type & SCAN_TCP_PORT) &&
              nmap_getservbyport(rangestart, "tcp")) {
            porttbl[rangestart] |= SCAN_TCP_PORT;
          }
          if ((range_type & SCAN_UDP_PORT) &&
              nmap_getservbyport(rangestart, "udp")) {
            porttbl[rangestart] |= SCAN_UDP_PORT;
          }
          if ((range_type & SCAN_SCTP_PORT) &&
              nmap_getservbyport(rangestart, "sctp")) {
            porttbl[rangestart] |= SCAN_SCTP_PORT;
          }
          if ((range_type & SCAN_PROTOCOLS) &&
              nmap_getprotbynum(rangestart)) {
            porttbl[rangestart] |= SCAN_PROTOCOLS;
          }
        } else {
          porttbl[rangestart] |= range_type;
        }
      }
      rangestart++;
    }

    /* Find the next range */
    while (isspace((int) (unsigned char) *current_range)) current_range++;

    if (*current_range == ']') {
      if (!nested)
        fatal("Unexpected ] character in port/protocol specification");
      return;
    }

    if (*current_range && *current_range != ',') {
      fatal("Error #488: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    if (*current_range == ',')
      current_range++;
  } while (current_range && *current_range);

}

/* This function returns the number of ports that remain after the excluded ports
  are removed from the ports. It places these ports at the start of the ports array. */
static int remaining_ports(unsigned short int *ports, int count, unsigned short int *exclude_ports, int exclude_count, const char *type) {
  static bool has_been_excluded[65536];
  int i, j;

  if (count == 0 || exclude_count == 0)
    return count;

  if (o.debugging > 1)
    // log_write(LOG_STDOUT, "Removed %s ports: ", type);
    printf("Removed %s ports: ", type);

  for (i = 0; i < 65536; i++)
    has_been_excluded[i] = false;
  for (i = 0; i < exclude_count; i++)
    has_been_excluded[exclude_ports[i]] = true;
  for (i = 0, j = 0; i < count; i++)
    if (!has_been_excluded[ports[i]])
      ports[j++] = ports[i];
    else if (o.debugging > 1)
      // log_write(LOG_STDOUT, "%d ", ports[i]);
      printf("%d ", ports[i]);

  if (o.debugging > 1) {
    if (count-j) {
      // log_write(LOG_STDOUT, "\n");
      printf("\n");
    } else {
      // log_write(LOG_STDOUT, "None\n");
      printf("None\n");
    }
  }
  if (o.debugging && count-j) {
    // log_write(LOG_STDOUT, "Removed %d %s ports that would have been considered for scanning otherwise.\n", count-j, type);
    printf("Removed %d %s ports that would have been considered for scanning otherwise.\n", count-j, type);
  }

  return j;
}