//our main.cpp is borrowed from nmap's nmap.cc
#include "base.h"
#include "timing.h"
#include "target.h"
#include "netutil.h"
#include "scanops.h"
#include "errorhandle.h"
#include "scan_lists.h"
#include "util.h"
#include "targets.h"
#include "xml.h"
#include "tcpip.h"
#include "services.h"
#include "MACLookup.h"
#include "charpool.h"
#include "output.h"
#include "portlist.h"
#include <cstdlib>//? I have stdlib.h in errorhandle.h
#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <netinet/in.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sstream>
#include <fstream>
#include <stdio.h>
using namespace std;

struct tm *local_time;

ScanOps o;
// static vector<string> route_dst_hosts;

struct scan_lists ports = { 0 };

/* A mechanism to save argv[0] for code that requires that. */
static const char *program_name = NULL;

// extern void set_program_name(const char *name);
static void our_welcome(){
	cout<<"/****************************************************/"<<endl;
	cout<<"/*                     WELCOME!                     */"<<endl;
	cout<<"/*                  Our OS Scan Demo                */"<<endl;
	cout<<"/****************************************************/"<<endl;
}

static void printusage(){
	cout<<"usage: please input least one scan target!"<<endl;
}

/* This struct is used is a temporary storage place that holds options that
   can't be correctly parsed and interpreted before the entire command line has
   been read. Examples are -6 and -S. Trying to set the source address without
   knowing the address family first could result in a failure if you pass an
   IPv6 address and the address family is still IPv4. */
static struct delayed_options {
public:
  delayed_options() {
    this->pre_max_parallelism   = -1;
    this->pre_scan_delay        = -1;
    this->pre_max_scan_delay    = -1;
    this->pre_init_rtt_timeout  = -1;
    this->pre_min_rtt_timeout   = -1;
    this->pre_max_rtt_timeout   = -1;
    this->pre_max_retries       = -1;
    this->pre_host_timeout      = -1;
#ifndef NOLUA
    this->pre_scripttimeout     = -1;
#endif
    this->iflist                = false;
    this->advanced              = false;
    this->af                    = AF_UNSPEC;
    this->decoys                = false;
  }

  // Pre-specified timing parameters.
  // These are stored here during the parsing of the arguments so that we can
  // set the defaults specified by any timing template options (-T2, etc) BEFORE
  // any of these. In other words, these always take precedence over the templates.
  int   pre_max_parallelism, pre_scan_delay, pre_max_scan_delay;
  int   pre_init_rtt_timeout, pre_min_rtt_timeout, pre_max_rtt_timeout;
  int   pre_max_retries;
  long  pre_host_timeout;
#ifndef NOLUA
  double pre_scripttimeout;
#endif
  char  *machinefilename, *kiddiefilename, *normalfilename, *xmlfilename;
  bool  iflist, decoys, advanced;
  char  *exclude_spec, *exclude_file;
  char  *spoofSource, *decoy_arguments;
  const char *spoofmac;
  int af;
  std::vector<std::string> verbose_out;

  void warn_deprecated (const char *given, const char *replacement) {
    std::ostringstream os;
    os << "Warning: The -" << given << " option is deprecated. Please use -" << replacement;
    this->verbose_out.push_back(os.str());
  }

} delayed_options;

void set_program_name(const char *name){
	program_name = name;
}

static const char *get_program_name(void) {
  return program_name;
}

void parse_options(int argc, char **argv){
	//remain to fill
}

#ifdef WIN32
static void check_setugid(void) {
}
#else
/* Show a warning when running setuid or setgid, as this allows code execution
   (for example NSE scripts) as the owner/group. */
static void check_setugid(void) {
  if (getuid() != geteuid())
    error("WARNING: Running Nmap setuid, as you are doing, is a major security risk.\n");
  if (getgid() != getegid())
    error("WARNING: Running Nmap setgid, as you are doing, is a major security risk.\n");
}
#endif

static void insert_port_into_merge_list(unsigned short *mlist,
                                        int *merged_port_count,
                                        unsigned short p) {
  int i;
  // make sure the port isn't already in the list
  for (i = 0; i < *merged_port_count; i++) {
    if (mlist[i] == p) {
      return;
    }
  }
  mlist[*merged_port_count] = p;
  (*merged_port_count)++;
}


static unsigned short *merge_port_lists(unsigned short *port_list1, int count1,
                                        unsigned short *port_list2, int count2,
                                        int *merged_port_count) {
  int i;
  unsigned short *merged_port_list = NULL;

  *merged_port_count = 0;

  merged_port_list =
    (unsigned short *) safe_zalloc((count1 + count2) * sizeof(unsigned short));

  for (i = 0; i < count1; i++) {
    insert_port_into_merge_list(merged_port_list,
                                merged_port_count,
                                port_list1[i]);
  }
  for (i = 0; i < count2; i++) {
    insert_port_into_merge_list(merged_port_list,
                                merged_port_count,
                                port_list2[i]);
  }

  // if there were duplicate ports then we can save some memory
  if (*merged_port_count < (count1 + count2)) {
    merged_port_list = (unsigned short*)
                       safe_realloc(merged_port_list,
                                    (*merged_port_count) * sizeof(unsigned short));
  }

  return merged_port_list;
}


void validate_scan_lists(scan_lists &ports, ScanOps &o) {
  if (o.pingtype == PINGTYPE_UNKNOWN) {
    if (o.isr00t) {
      if (o.pf() == PF_INET) {
        o.pingtype = DEFAULT_IPV4_PING_TYPES;
      } else {
        o.pingtype = DEFAULT_IPV6_PING_TYPES;
      }
      getpts_simple(DEFAULT_PING_ACK_PORT_SPEC, SCAN_TCP_PORT,
                    &ports.ack_ping_ports, &ports.ack_ping_count);
      getpts_simple(DEFAULT_PING_SYN_PORT_SPEC, SCAN_TCP_PORT,
                    &ports.syn_ping_ports, &ports.syn_ping_count);
    } else {
      o.pingtype = PINGTYPE_TCP; // if nonr00t
      getpts_simple(DEFAULT_PING_CONNECT_PORT_SPEC, SCAN_TCP_PORT,
                    &ports.syn_ping_ports, &ports.syn_ping_count);
    }
  }

  if ((o.pingtype & PINGTYPE_TCP) && (!o.isr00t)) {
    // We will have to do a connect() style ping
    // Pretend we wanted SYN probes all along.
    if (ports.ack_ping_count > 0) {
      // Combine the ACK and SYN ping port lists since they both reduce to
      // SYN probes in this case
      unsigned short *merged_port_list;
      int merged_port_count;

      merged_port_list = merge_port_lists(
                           ports.syn_ping_ports, ports.syn_ping_count,
                           ports.ack_ping_ports, ports.ack_ping_count,
                           &merged_port_count);

      // clean up a bit
      free(ports.syn_ping_ports);
      free(ports.ack_ping_ports);

      ports.syn_ping_count = merged_port_count;
      ports.syn_ping_ports = merged_port_list;
      ports.ack_ping_count = 0;
      ports.ack_ping_ports = NULL;
    }
    o.pingtype &= ~PINGTYPE_TCP_USE_ACK;
    o.pingtype |= PINGTYPE_TCP_USE_SYN;
  }

#ifndef WIN32 /*  Win32 has perfectly fine ICMP socket support */
  if (!o.isr00t) {
    if (o.pingtype & (PINGTYPE_ICMP_PING | PINGTYPE_ICMP_MASK | PINGTYPE_ICMP_TS)) {
      error("Warning:  You are not root -- using TCP pingscan rather than ICMP");
      o.pingtype = PINGTYPE_TCP;
      if (ports.syn_ping_count == 0) {
        getpts_simple(DEFAULT_TCP_PROBE_PORT_SPEC, SCAN_TCP_PORT, &ports.syn_ping_ports, &ports.syn_ping_count);
        assert(ports.syn_ping_count > 0);
      }
    }
  }
#endif
}

// Free some global memory allocations.
// This is used for detecting memory leaks.
void nmap_free_mem() {
  PortList::freePortMap();
  cp_free();//temporarily add it. Is it necessary?
  free_services();
  // AllProbes::service_scan_free();
  // traceroute_hop_cache_clear();
  // nsock_set_default_engine(NULL);
}

void  apply_delayed_options() {
  int i;
  char tbuf[128];
  struct sockaddr_storage ss;
  size_t sslen;

  // Default IPv4
  o.setaf(delayed_options.af == AF_UNSPEC ? AF_INET : delayed_options.af);

  if (o.verbose > 0) {
    for (std::vector<std::string>::iterator it = delayed_options.verbose_out.begin(); it != delayed_options.verbose_out.end(); ++it) {
      error("%s", it->c_str());
    }
  }
  delayed_options.verbose_out.clear();

  if (delayed_options.advanced) {
    o.servicescan = true;
// #ifndef NOLUA
//     o.script = true;
// #endif
    if (o.isr00t) {
      o.osscan = true;
      o.traceroute = true;
    }
  }
  if (o.spoofsource) {
    int rc = resolve(delayed_options.spoofSource, 0, &ss, &sslen, o.af());
    if (rc != 0) {
      fatal("Failed to resolve/decode supposed %s source address \"%s\": %s",
        (o.af() == AF_INET) ? "IPv4" : "IPv6", delayed_options.spoofSource,
        gai_strerror(rc));
    }
    o.setSourceSockAddr(&ss, sslen);
  }
  // After the arguments are fully processed we now make any of the timing
  // tweaks the user might've specified:
  if (delayed_options.pre_max_parallelism != -1)
    o.max_parallelism = delayed_options.pre_max_parallelism;
  if (delayed_options.pre_scan_delay != -1) {
    o.scan_delay = delayed_options.pre_scan_delay;
    if (o.scan_delay > o.maxTCPScanDelay())
      o.setMaxTCPScanDelay(o.scan_delay);
    if (o.scan_delay > o.maxUDPScanDelay())
      o.setMaxUDPScanDelay(o.scan_delay);
    if (o.scan_delay > o.maxSCTPScanDelay())
      o.setMaxSCTPScanDelay(o.scan_delay);
    if (delayed_options.pre_max_parallelism != -1 || o.min_parallelism != 0)
      error("Warning: --min-parallelism and --max-parallelism are ignored with --scan-delay.");
  }
  if (delayed_options.pre_max_scan_delay != -1) {
    o.setMaxTCPScanDelay(delayed_options.pre_max_scan_delay);
    o.setMaxUDPScanDelay(delayed_options.pre_max_scan_delay);
    o.setMaxSCTPScanDelay(delayed_options.pre_max_scan_delay);
  }
  if (delayed_options.pre_init_rtt_timeout != -1)
    o.setInitialRttTimeout(delayed_options.pre_init_rtt_timeout);
  if (delayed_options.pre_min_rtt_timeout != -1)
    o.setMinRttTimeout(delayed_options.pre_min_rtt_timeout);
  if (delayed_options.pre_max_rtt_timeout != -1)
    o.setMaxRttTimeout(delayed_options.pre_max_rtt_timeout);
  if (delayed_options.pre_max_retries != -1)
    o.setMaxRetransmissions(delayed_options.pre_max_retries);
  if (delayed_options.pre_host_timeout != -1)
    o.host_timeout = delayed_options.pre_host_timeout;
// #ifndef NOLUA
//   if (delayed_options.pre_scripttimeout != -1)
//     o.scripttimeout = delayed_options.pre_scripttimeout;
// #endif


  if (o.osscan) {
    if (o.af() == AF_INET)
        o.reference_FPs = parse_fingerprint_reference_file("nmap-os-db");
    // else if (o.af() == AF_INET6)
    //     o.os_labels_ipv6 = load_fp_matches();
      else
        printf("Sorry, we do not support ipv6 os_scan.\n");
  }

  // Must check and change this before validate_scan_lists
  if (o.pingtype & PINGTYPE_NONE)
    o.pingtype = PINGTYPE_NONE;

  validate_scan_lists(ports, o);
  o.ValidateOptions();

  // print ip options
  if ((o.debugging || o.packetTrace()) && o.ipoptionslen) {
    char buf[256]; // 256 > 5*40
    bintohexstr(buf, sizeof(buf), (char*) o.ipoptions, o.ipoptionslen);
    if (o.ipoptionslen >= 8)       // at least one ip address
      // log_write(LOG_STDOUT, "Binary ip options to be send:\n%s", buf);
      printf("Binary ip options to be send:\n%s", buf);
    // log_write(LOG_STDOUT, "Parsed ip options to be send:\n%s\n",
    //           format_ip_options(o.ipoptions, o.ipoptionslen));
    printf("Parsed ip options to be send:\n%s\n",
              format_ip_options(o.ipoptions, o.ipoptionslen));
  }

  /* Open the log files, now that we know whether the user wants them appended
     or overwritten */
  // something related to log
  // if (delayed_options.normalfilename) {
  //   log_open(LOG_NORMAL, o.append_output, delayed_options.normalfilename);
  //   free(delayed_options.normalfilename);
  // }
  // if (delayed_options.machinefilename) {
  //   log_open(LOG_MACHINE, o.append_output, delayed_options.machinefilename);
  //   free(delayed_options.machinefilename);
  // }
  // if (delayed_options.kiddiefilename) {
  //   log_open(LOG_SKID, o.append_output, delayed_options.kiddiefilename);
  //   free(delayed_options.kiddiefilename);
  // }
  // if (delayed_options.xmlfilename) {
  //   log_open(LOG_XML, o.append_output, delayed_options.xmlfilename);
  //   free(delayed_options.xmlfilename);
  // }

  if (o.verbose > 1)//actually it is useless too
    o.reason = true;

  // ISO 8601 date/time -- http://www.cl.cam.ac.uk/~mgk25/iso-time.html
  if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", local_time) <= 0)
    fatal("Unable to properly format time");
  // log_write(LOG_STDOUT | LOG_SKID, "Starting %s %s ( %s ) at %s\n", NMAP_NAME, NMAP_VERSION, NMAP_URL, tbuf);
  
  //I think it is meaningless to print the version of nmap

  // printf("Starting %s %s ( %s ) at %s\n", NMAP_NAME, NMAP_VERSION, NMAP_URL, tbuf);
  // if (o.verbose) {
  //   if (local_time->tm_mon == 8 && local_time->tm_mday == 1) {
  //     log_write(LOG_STDOUT | LOG_SKID, "Happy %dth Birthday to Nmap, may it live to be %d!\n", local_time->tm_year - 97, local_time->tm_year + 3);
  //   } else if (local_time->tm_mon == 11 && local_time->tm_mday == 25) {
  //     log_write(LOG_STDOUT | LOG_SKID, "Nmap wishes you a merry Christmas! Specify -sX for Xmas Scan (https://nmap.org/book/man-port-scanning-techniques.html).\n");
  //   }
  // }

// #ifndef NOLUA
//   if (o.scripthelp) {
//      Special-case open_nse for --script-help only. 
//     open_nse();
//     exit(0);
//   }
// #endif

  if (o.traceroute && !o.isr00t)
    fatal("Traceroute has to be run as root");
  if (o.traceroute && o.idlescan)
    fatal("Traceroute does not support idle scan");

  if ((o.noportscan) && (o.portlist || o.fastscan))
    fatal("You cannot use -F (fast scan) or -p (explicit port selection) when not doing a port scan");

  if (o.portlist && o.fastscan)
    fatal("You cannot use -F (fast scan) with -p (explicit port selection) but see --top-ports and --port-ratio to fast scan a range of ports");

  if (o.ipprotscan) {
    if (o.portlist)
      getpts(o.portlist, &ports);
    else
      getpts((char *) (o.fastscan ? "[P:0-]" : "0-"), &ports);  // Default protocols to scan
  } else if (!o.noportscan) {
    gettoppts(o.topportlevel, o.portlist, &ports, o.exclude_portlist);
  }

  // Uncomment the following line to use the common lisp port spec test suite
  //printf("port spec: (%d %d %d %d)\n", ports.tcp_count, ports.udp_count, ports.sctp_count, ports.prot_count); exit(0);

#ifdef WIN32
  if (o.sendpref & PACKET_SEND_IP) {
    error("WARNING: raw IP (rather than raw ethernet) packet sending attempted on Windows. This probably won't work.  Consider --send-eth next time.");
  }
#endif
  if (delayed_options.spoofmac) {
    u8 mac_data[6];
    int pos = 0; /* Next index of mac_data to fill in */
    char tmphex[3];
    /* A zero means set it all randomly.  Anything that is all digits
       or colons is treated as a prefix, with remaining characters for
       the 6-byte MAC (if any) chosen randomly.  Otherwise, it is
       treated as a vendor string for lookup in nmap-mac-prefixes */
    if (strcmp(delayed_options.spoofmac, "0") == 0) {
      pos = 0;
    } else {
      const char *p = delayed_options.spoofmac;
      while (*p) {
        if (*p == ':')
          p++;
        if (isxdigit((int) (unsigned char) *p) && isxdigit((int) (unsigned char) * (p + 1))) {
          if (pos >= 6)
            fatal("Bogus --spoof-mac value encountered (%s) -- only up to 6 bytes permitted", delayed_options.spoofmac);
          tmphex[0] = *p;
          tmphex[1] = *(p + 1);
          tmphex[2] = '\0';
          mac_data[pos] = (u8) strtol(tmphex, NULL, 16);
          pos++;
          p += 2;
        } else break;
      }
      if (*p) {
        /* Failed to parse it as a MAC prefix -- treating as a vendor substring instead */
        if (!MACCorp2Prefix(delayed_options.spoofmac, mac_data))
          fatal("Could not parse as a prefix nor find as a vendor substring the given --spoof-mac argument: %s.  If you are giving hex digits, there must be an even number of them.", delayed_options.spoofmac);
        pos = 3;
      }
    }
    if (pos < 6) {
      get_random_bytes(mac_data + pos, 6 - pos);
    }
    /* Got the new MAC! */
    const char *vend = MACPrefix2Corp(mac_data);
    // log_write(LOG_PLAIN,
    //           "Spoofing MAC address %02X:%02X:%02X:%02X:%02X:%02X (%s)\n",
    //           mac_data[0], mac_data[1], mac_data[2], mac_data[3], mac_data[4],
    //           mac_data[5], vend ? vend : "No registered vendor");
    printf("Spoofing MAC address %02X:%02X:%02X:%02X:%02X:%02X (%s)\n",
              mac_data[0], mac_data[1], mac_data[2], mac_data[3], mac_data[4],
              mac_data[5], vend ? vend : "No registered vendor");
    o.setSpoofMACAddress(mac_data);

    /* If they want to spoof the MAC address, we should at least make
       some effort to actually send raw ethernet frames rather than IP
       packets (which would use the real IP */
    if (o.sendpref != PACKET_SEND_IP_STRONG)
      o.sendpref = PACKET_SEND_ETH_STRONG;
  }

  /* Warn if setuid/setgid. */
  check_setugid();

  /* Remove any ports that are in the exclusion list */
  removepts(o.exclude_portlist, &ports);

  /* By now, we've got our port lists.  Give the user a warning if no
   * ports are specified for the type of scan being requested.  Other things
   * (such as OS ident scan) might break cause no ports were specified,  but
   * we've given our warning...
   */
  if ((o.TCPScan()) && ports.tcp_count == 0)
    error("WARNING: a TCP scan type was requested, but no tcp ports were specified.  Skipping this scan type.");
  if (o.SCTPScan() && ports.sctp_count == 0)
    error("WARNING: a SCTP scan type was requested, but no sctp ports were specified.  Skipping this scan type.");
  if (o.UDPScan() && ports.udp_count == 0)
    error("WARNING: UDP scan was requested, but no udp ports were specified.  Skipping this scan type.");
  if (o.ipprotscan && ports.prot_count == 0)
    error("WARNING: protocol scan was requested, but no protocols were specified to be scanned.  Skipping this scan type.");

  if (o.pingtype & PINGTYPE_TCP && ports.syn_ping_count+ports.ack_ping_count == 0)
    error("WARNING: a TCP ping scan was requested, but after excluding requested TCP ports, none remain. Skipping this scan type.");
  if (o.pingtype & PINGTYPE_UDP && ports.udp_ping_count == 0)
    error("WARNING: a UDP ping scan was requested, but after excluding requested UDP ports, none remain. Skipping this scan type.");
  if (o.pingtype & PINGTYPE_SCTP_INIT && ports.sctp_ping_count == 0)
    error("WARNING: a SCTP ping scan was requested, but after excluding requested SCTP ports, none remain. Skipping this scan type.");
  if (o.pingtype & PINGTYPE_PROTO && ports.proto_ping_count == 0)
    error("WARNING: a IP Protocol ping scan was requested, but after excluding requested protocols, none remain. Skipping this scan type.");


  /* We need to find what interface to route through if:
   * --None have been specified AND
   * --We are root and doing tcp ping OR
   * --We are doing a raw sock scan and NOT pinging anyone */
  if (o.SourceSockAddr() && !*o.device) {
    if (ipaddr2devname(o.device, o.SourceSockAddr()) != 0) {
      fatal("Could not figure out what device to send the packet out on with the source address you gave me!  If you are trying to sp00f your scan, this is normal, just give the -e eth0 or -e ppp0 or whatever.  Otherwise you can still use -e, but I find it kind of fishy.");
    }
  }

  if (*o.device && !o.SourceSockAddr()) {
    struct sockaddr_storage tmpsock;
    memset(&tmpsock, 0, sizeof(tmpsock));
    if (devname2ipaddr(o.device, &tmpsock) == -1) {
      fatal("I cannot figure out what source address to use for device %s, does it even exist?", o.device);
    }
    o.setSourceSockAddr(&tmpsock, sizeof(tmpsock));
  }

  if (delayed_options.exclude_file) {
    o.excludefd = fopen(delayed_options.exclude_file, "r");
    if (!o.excludefd)
      fatal("Failed to open exclude file %s for reading", delayed_options.exclude_file);
    free(delayed_options.exclude_file);
  }
  o.exclude_spec = delayed_options.exclude_spec;

  if (delayed_options.decoy_arguments) {
    char *p = delayed_options.decoy_arguments, *q;
    do {
      q = strchr(p, ',');
      if (q)
        *q = '\0';
      if (!strcasecmp(p, "me")) {
        if (o.decoyturn != -1)
          fatal("Can only use 'ME' as a decoy once.\n");
        o.decoyturn = o.numdecoys++;
      } else if (!strcasecmp(p, "rnd") || !strncasecmp(p, "rnd:", 4)) {
        if (delayed_options.af == AF_INET6)
          fatal("Random decoys can only be used with IPv4");
        int i = 1;

        /* 'rnd:' is allowed and just gives them one */
        if (strlen(p) > 4)
          i = atoi(&p[4]);

        if (i < 1)
          fatal("Bad 'rnd' decoy \"%s\"", p);

        if (o.numdecoys + i >= MAX_DECOYS - 1)
          fatal("You are only allowed %d decoys (if you need more redefine MAX_DECOYS in nmap.h)", MAX_DECOYS);

        while (i--) {
          do {
            ((struct sockaddr_in *)&o.decoys[o.numdecoys])->sin_addr.s_addr = get_random_u32();
          } while (ip_is_reserved(&((struct sockaddr_in *)&o.decoys[o.numdecoys])->sin_addr));
          o.numdecoys++;
        }
      } else {
        if (o.numdecoys >= MAX_DECOYS - 1)
          fatal("You are only allowed %d decoys (if you need more redefine MAX_DECOYS in nmap.h)", MAX_DECOYS);

        /* Try to resolve it */
        struct sockaddr_storage decoytemp;
        size_t decoytemplen = sizeof(struct sockaddr_storage);
        int rc;
        if (delayed_options.af == AF_INET6){
          rc = resolve(p, 0, (sockaddr_storage*)&decoytemp, &decoytemplen, AF_INET6);
        }
        else
          rc = resolve(p, 0, (sockaddr_storage*)&decoytemp, &decoytemplen, AF_INET);
        if (rc != 0)
          fatal("Failed to resolve decoy host \"%s\": %s", p, gai_strerror(rc));
        o.decoys[o.numdecoys] = decoytemp;
        o.numdecoys++;
      }
      if (q) {
        *q = ',';
        p = q + 1;
      }
    } while (q);
  }
  /* Set up host address also in array of decoys! */
  if (o.decoyturn == -1) {
    o.decoyturn = (o.numdecoys == 0) ?  0 : get_random_uint() % o.numdecoys;
    o.numdecoys++;
    for (i = o.numdecoys - 1; i > o.decoyturn; i--)
      o.decoys[i] = o.decoys[i - 1];
  }
}


//  string itos(int i)  
// {  
//     ostringstream os;  
//     os<<i;  
//     string result;  
//     istringstream is(os.str());  
//     is>>result;  
//     return result;  
  
// } 


//  string longtos(unsigned long i)     //改一下函数名，改一下类型，搞定  
// {  
//     ostringstream os;  
//     os<<i;  
//     string result;  
//     istringstream is(os.str());  
//     is>>result;  
//     return result;  
// }

template <typename T>
string num2s(T i){
  ostringstream os;
  os << i;
  string result;  
  istringstream is(os.str());  
  is>>result;  
  return result; 
}

static void write_our_log(FILE *fout, target_in_file *t,Target *tmp){
	PortInfo *p_pi;
  char macascii[32];
	list<PortInfo>::iterator iterPIList;
  string tmp_s;
  tmp_s = "Num:" + num2s(t->target_id);
  tmp_s.append("\n");
	// fout<<"Num:"<<t->target_id<<"\n";
  fputs(tmp_s.c_str(),fout);
  tmp_s = "Ip:" + string(t->target_ip);
  tmp_s.append("\n");
  fputs(tmp_s.c_str(),fout);
 
  const u8 *mac = tmp->MACAddress();
  t->mac = "";
  if (mac) {
    int a=Snprintf(macascii, sizeof(macascii), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
   t->mac += macascii;
  }
  
	if(t->address_family == AF_INET){
    tmp_s = "addressFamily:ipv4\n";
    fputs(tmp_s.c_str(),fout);
   
    }
	else
  {
		// fout<<"addressFamily:"<<"ipv6"<<"\n";
    tmp_s = "addressFamily:ipv6\n";
    fputs(tmp_s.c_str(),fout);
   }
  
	//fout<<"startTime:"<<t->starttime<<"\n";
  tmp_s = "startTime:" + num2s(t->starttime);
  tmp_s.append("\n");
  fputs(tmp_s.c_str(),fout);
	//fout<<"endTime:"<<t->endtime<<"\n";
 
  tmp_s = "endTime:" + num2s(t->endtime);
  tmp_s.append("\n");
  fputs(tmp_s.c_str(),fout);
 
	if("" == (t->os_name))
		// fout<<"NULL"<<"\n";
    {
   tmp_s = "os:NULL\n";
   fputs(tmp_s.c_str(),fout);

    }
	else
		// fout<<"os:"<<t->os_name<<"\n";
  {
    tmp_s = "os:" + string(t->os_name);
    tmp_s.append("\n");
    fputs(tmp_s.c_str(),fout);
    
  }
	if("" == (t->device_type))
		// fout<<"NULL"<<"\n";
  {
  tmp_s = "deviceType:NULL\n";
  fputs(tmp_s.c_str(),fout);
  }
	else
		// fout<<"deviceType:"<<t->device_type<<"\n";
  {
  tmp_s = "deviceType:" + string(t->device_type);
  tmp_s.append("\n");
  fputs(tmp_s.c_str(),fout);
  }
  if("" == (t->mac))
		// fout<<"NULL"<<"\n";
  {
  tmp_s = "mac:NULL\n";
  fputs(tmp_s.c_str(),fout);
  }
	else
    // fout << "mac:"<<t->mac <<"\n";
  {
    tmp_s = "mac:" + string(t->mac);
    tmp_s.append("\n");
  fputs(tmp_s.c_str(),fout);
  }
		// fout<<"MAC:"<<mac[0]<<":"<<mac[1]<<":"<<mac[2]<<":"<<mac[3]<<":"<<mac[4]<<":"<<mac[5]<<":"<<endl;
    // cout << t->mac << "**************************"<< endl;
	int count = 0;
	// fout<<"start"<<"\n";
  tmp_s = "start\n";
  fputs(tmp_s.c_str(), fout);
	for(iterPIList = t->PortInfoList.begin();iterPIList != t->PortInfoList.end();iterPIList++){
		p_pi = &(*iterPIList);
		// fout << p_pi->portno <<"\t"<<p_pi->protocol<<"\t"<<p_pi->state<<"\t"<<p_pi->serviceinfo<<"\n";
   tmp_s = num2s(p_pi->portno);
   tmp_s.append("\t");
   tmp_s.append(p_pi->protocol);
   tmp_s.append("\t");
   tmp_s.append(p_pi->state);
   tmp_s.append("\t");
   tmp_s.append(p_pi->serviceinfo);
   tmp_s.append("\n");
  fputs(tmp_s.c_str(),fout);
		if(p_pi->state=="open")
		  count++;
	}
	// fout<<"end"<<"\n";
  tmp_s = "end\n";
  fputs(tmp_s.c_str(),fout);
	// fout<<"openNum:"<<count<<"\n";
  tmp_s = "openNum:" + num2s(count);
  tmp_s.append("\n");
  fputs(tmp_s.c_str(),fout);

  tmp_s = "\n";
  fputs(tmp_s.c_str(),fout);
}





int main(int argc, char *argv[]){
	our_welcome();
	set_program_name(argv[0]);
	//cout<<argv[0]<<endl;
	//argv[0] indicates the name of our program
	/***************test of libpcap***************/
	char errBuf[PCAP_ERRBUF_SIZE], * device;  
	
	device = pcap_lookupdev(errBuf);  
	    
	if(device){
		printf("success:device: %s\n",device);
	}
	else  
	{  
	    	printf("error: %s\n", errBuf);  
	}
	//***********end of libpcap test*************/
	if(argc < 2){//at least one argument
		printusage();
		exit(-1);
	}
	//let's start
	if(argv[1]){
		cout<<"Scan target: "<<argv[1]<<endl;
	}
	vector<Target *> Targets;//vital
	time_t now;
	struct hostent *target = NULL;/*for hostent, all addresses are supplied in host order,
					and returned in network order*/					
	time_t timep;
	char mytime[128];
	addrset exclude_group;
	unsigned int ideal_scan_group_sz = 0;
	Target *currenths;
	char myname[FQDN_LEN + 1];
	int sourceaddrwarning = 0;//Have we warned them yet about unguessable source addresses?
	unsigned int targetno;
	char hostname[FQDN_LEN + 1] = "";
	struct sockaddr_storage ss;//in netinet/in.h, this structure seems different from that in ws2def.h
	size_t sslen;
	//here we ignore something about log
	now = time(NULL);
	local_time = localtime(&now);

	Targets.reserve(100);//I don't know why
	parse_options(argc, argv);//actually we did nothing here

	//tty_init();
	//put the keyboard in raw mode
  //It seems useless
	
	apply_delayed_options();
	//route_dst_hosts?! useless
  //codes below had never been reached in our windows version
	/*
	for (unsigned int i = 0; i < route_dst_hosts.size(); i++) {
		const char *dst;
		struct sockaddr_storage ss;
	    	struct route_nfo rnfo;
	    	size_t sslen;
	    	int rc;
		
	    	dst = route_dst_hosts[i].c_str();
	    	rc = resolve(dst, 0, &ss, &sslen, o.af());
		
	    	if (rc != 0)
	      		//fatal("Can't resolve %s: %s.", dst, gai_strerror(rc));
	      		fatal("Can't resolve %s.", dst);
	    
	    	printf("%s\n", inet_ntop_ez(&ss, sslen));
		
	    	if (!route_dst(&ss, &rnfo, o.device, o.SourceSockAddr())) {
	      		printf("Can't route %s (%s).", dst, inet_ntop_ez(&ss, sslen));
	    	} else {
	      		printf("%s %s", rnfo.ii.devname, rnfo.ii.devfullname);
	      		printf(" srcaddr %s", inet_ntop_ez(&rnfo.srcaddr, sizeof(rnfo.srcaddr)));
	      		if (rnfo.direct_connect)
				printf(" direct");
	      		else
				printf(" nexthop %s", inet_ntop_ez(&rnfo.nexthop, sizeof(rnfo.nexthop)));
	    		}
	    	printf("\n");
	  }
	  route_dst_hosts.clear();
	*/
	  //here are some actions on iflist
	  //wow, print it; it seems useless
	  //ignore it

	  //many many

	    /* Before we randomize the ports scanned, we must initialize PortList class. */
	if (o.ipprotscan)
	  PortList::initializePortMap(IPPROTO_IP,  ports.prots, ports.prot_count);
	if (o.TCPScan())
	  PortList::initializePortMap(IPPROTO_TCP, ports.tcp_ports, ports.tcp_count);
	if (o.UDPScan())
	  PortList::initializePortMap(IPPROTO_UDP, ports.udp_ports, ports.udp_count);
	if (o.SCTPScan())
	  PortList::initializePortMap(IPPROTO_SCTP, ports.sctp_ports, ports.sctp_count);

	if (o.randomize_ports) {
    	if (ports.tcp_count) {
      		shortfry(ports.tcp_ports, ports.tcp_count);
      		// move a few more common ports closer to the beginning to speed scan
      		random_port_cheat(ports.tcp_ports, ports.tcp_count);
    	}
    	if (ports.udp_count)
      		shortfry(ports.udp_ports, ports.udp_count);
    	if (ports.sctp_count)
      		shortfry(ports.sctp_ports, ports.sctp_count);
    	if (ports.prot_count)
      		shortfry(ports.prots, ports.prot_count);
  	}

  	addrset_init(&exclude_group);//attention please!
  	//something related to exclude_group...

  	//something related to scripts
  	if (o.ping_group_sz < o.minHostGroupSz())
    	o.ping_group_sz = o.minHostGroupSz();
    //be ready for host discovery
    //construction of HostGroupState received user input arguments
  	HostGroupState hstate(o.ping_group_sz, o.randomize_hosts, argc, (const char **) argv);
  do {
    ideal_scan_group_sz = determineScanGroupSize(o.numhosts_scanned, &ports);

    while (Targets.size() < ideal_scan_group_sz) {
      o.current_scantype = HOST_DISCOVERY;
      currenths = nexthost(&hstate, &exclude_group, &ports, o.pingtype);
      if (!currenths)
        break;
    
      if (currenths->flags & HOST_UP && !o.listscan)
        o.numhosts_up++;

      if ((o.noportscan && !o.traceroute /*&& !o.script*/) || o.listscan) {
        // We're done with the hosts
        if (currenths->flags & HOST_UP || (o.verbose && !o.openOnly())) {
          xml_start_tag("host");
          write_host_header(currenths);
          printmacinfo(currenths);
          //  if (currenths->flags & HOST_UP)
          //  log_write(LOG_PLAIN,"\n");
          printtimes(currenths);
          xml_end_tag();
          xml_newline();
          // log_flush_all();
          //I think that codes related to log is useless
        }
        delete currenths;
        o.numhosts_scanned++;
        if (!o.max_ips_to_scan || o.max_ips_to_scan > o.numhosts_scanned + Targets.size())
          continue;
        else
          break;
      }

      if (o.spoofsource) {
        o.SourceSockAddr(&ss, &sslen);
        currenths->setSourceSockAddr(&ss, sslen);
      }

      // I used to check that !currenths->weird_responses, but in some
      // rare cases, such IPs CAN be port successfully scanned and even
      // connected to
      if (!(currenths->flags & HOST_UP)) {
        if (o.verbose && (!o.openOnly() || currenths->ports.hasOpenPorts())) {
          xml_start_tag("host");
          write_host_header(currenths);
          xml_end_tag();
          xml_newline();
        }
        delete currenths;
        o.numhosts_scanned++;
        if (!o.max_ips_to_scan || o.max_ips_to_scan > o.numhosts_scanned + Targets.size())
          continue;
        else
          break;
      }

      if (o.RawScan()) {
        if (currenths->SourceSockAddr(NULL, NULL) != 0) {
          if (o.SourceSockAddr(&ss, &sslen) == 0) {
            currenths->setSourceSockAddr(&ss, sslen);
          } else {
            if (gethostname(myname, FQDN_LEN) ||
                resolve(myname, 0, &ss, &sslen, o.af()) != 0)
              fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n");

            o.setSourceSockAddr(&ss, sslen);
            currenths->setSourceSockAddr(&ss, sslen);
            if (! sourceaddrwarning) {
              error("WARNING: We could not determine for sure which interface to use, so we are guessing %s .  If this is wrong, use -S <my_IP_address>.",
                    inet_socktop(&ss));//there are two types of inet_socktop(). one is in tcpip.h while the other one is in utils.h
              sourceaddrwarning = 1;
            }
          }
        }

        if (!currenths->deviceName())
          fatal("Do not have appropriate device name for target");

        // Hosts in a group need to be somewhat homogeneous. Put this host in
        // the next group if necessary. See target_needs_new_hostgroup for the
        // details of when we need to split.
        if (Targets.size() && target_needs_new_hostgroup(&Targets[0], Targets.size(), currenths)) {
          returnhost(&hstate);
          o.numhosts_up--;
          break;
        }
        o.decoys[o.decoyturn] = currenths->source();
      }
      Targets.push_back(currenths);
    }//THE END OF INNER WHILE LOOP
    
    if (Targets.size() == 0)
      break; // Couldn't find any more targets

    // Set the variable for status printing
    o.numhosts_scanning = Targets.size();

    // Our source must be set in decoy list because nexthost() call can
    // change it (that issue really should be fixed when possible)
    if (o.RawScan())
      o.decoys[o.decoyturn] = Targets[0]->source();

    // I now have the group for scanning in the Targets vector

    if (!o.noportscan) {
      // Ultra_scan sets o.scantype for us so we don't have to worry
      if (o.synscan)
        ultra_scan(Targets, &ports, SYN_SCAN);

      if (o.ackscan)
        ultra_scan(Targets, &ports, ACK_SCAN);

      if (o.windowscan)
        ultra_scan(Targets, &ports, WINDOW_SCAN);

      if (o.finscan)
        ultra_scan(Targets, &ports, FIN_SCAN);

      if (o.xmasscan)
        ultra_scan(Targets, &ports, XMAS_SCAN);

      if (o.nullscan)
        ultra_scan(Targets, &ports, NULL_SCAN);

      if (o.maimonscan)
        ultra_scan(Targets, &ports, MAIMON_SCAN);

      if (o.udpscan)
        ultra_scan(Targets, &ports, UDP_SCAN);

      if (o.connectscan)
        ultra_scan(Targets, &ports, CONNECT_SCAN);

      if (o.sctpinitscan)
        ultra_scan(Targets, &ports, SCTP_INIT_SCAN);

      if (o.sctpcookieechoscan)
        ultra_scan(Targets, &ports, SCTP_COOKIE_ECHO_SCAN);

      if (o.ipprotscan)
        ultra_scan(Targets, &ports, IPPROT_SCAN);
    /*	codes below are useless according to our windows version
      // These lame functions can only handle one target at a time
      if (o.idlescan) {
        for (targetno = 0; targetno < Targets.size(); targetno++) {
          o.current_scantype = IDLE_SCAN;
          keyWasPressed(); // Check if a status message should be printed
          idle_scan(Targets[targetno], ports.tcp_ports,
                    ports.tcp_count, o.idleProxy, &ports);
        }
      }
      if (o.bouncescan) {
        for (targetno = 0; targetno < Targets.size(); targetno++) {
          o.current_scantype = BOUNCE_SCAN;
          keyWasPressed(); // Check if a status message should be printed
          if (ftp.sd <= 0)
            ftp_anon_connect(&ftp);
          if (ftp.sd > 0)
            bounce_scan(Targets[targetno], ports.tcp_ports, ports.tcp_count, &ftp);
        }
      }

      if (o.servicescan) {
        o.current_scantype = SERVICE_SCAN;
        service_scan(Targets);
      }*/
    }

    if (o.osscan) {
      OSScan os_engine;
      os_engine.os_scan(Targets);
    }
/*
    if (o.traceroute)
      traceroute(Targets);

#ifndef NOLUA
    if (o.script || o.scriptversion) {
      script_scan(Targets, SCRIPT_SCAN);
    }
#endif
*/
    FILE *fout;
		fout = fopen("our_log.txt","ab+");
    for (targetno = 0; targetno < Targets.size(); targetno++) {
       currenths = Targets[targetno];
       target_in_file test_in_file;
			test_in_file.address_family = o.af();
			test_in_file.target_id = targetno;
      // Now I can do the output and such for each host
      if (currenths->timedOut(NULL)) {
        xml_open_start_tag("host");
        xml_attribute("starttime", "%lu", (unsigned long) currenths->StartTime());
        xml_attribute("endtime", "%lu", (unsigned long) currenths->EndTime());
        xml_close_start_tag();
        write_host_header(currenths);
        test_in_file.target_ip = currenths->NameIP();
        xml_end_tag(); // host
        xml_newline();
        // log_write(LOG_PLAIN, "Skipping host %s due to host timeout\n",
        //           currenths->NameIP(hostname, sizeof(hostname)));
        // log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Timeout\n",
        //           currenths->targetipstr(), currenths->HostName());
        printf("Skipping host %s due to host timeout\n",
                  currenths->NameIP(hostname, sizeof(hostname)));
        printf("Host: %s (%s)\tStatus: Timeout\n",
                  currenths->targetipstr(), currenths->HostName());
      } else {
        // --open means don't show any hosts without open ports.
        if (o.openOnly() && !currenths->ports.hasOpenPorts())
          continue;
        
        
        xml_open_start_tag("host");
        xml_attribute("starttime", "%lu", (unsigned long) currenths->StartTime());
        xml_attribute("endtime", "%lu", (unsigned long) currenths->EndTime());
        test_in_file.starttime = (unsigned long) currenths->StartTime();
				test_in_file.endtime = (unsigned long) currenths->EndTime();
        xml_close_start_tag();
        write_host_header(currenths);
        test_in_file.target_ip = currenths->NameIP();
        printportoutput(currenths, &currenths->ports,&test_in_file);
        printmacinfo(currenths);
    
        printosscanoutput(currenths,&test_in_file);
    
        // printserviceinfooutput(currenths);
// #ifndef NOLUA
//         printhostscriptresults(currenths);
// #endif
        // if (o.traceroute)
        //   printtraceroute(currenths);
        printtimes(currenths);
        // log_write(LOG_PLAIN | LOG_MACHINE, "\n");
        printf("\n");
        xml_end_tag(); // host
        xml_newline();
      }

				write_our_log(fout,&test_in_file,currenths);
         
    }
    fclose(fout);
    // log_flush_all();

    o.numhosts_scanned += Targets.size();

    // Free all of the Targets
    while (!Targets.empty()) {
      currenths = Targets.back();
      delete currenths;
      Targets.pop_back();
    }
    o.numhosts_scanning = 0;
  } while (!o.max_ips_to_scan || o.max_ips_to_scan > o.numhosts_scanned);
  //THE END OF PREVIOUS DO-WHILE LOOP

  addrset_free(&exclude_group);

  if (o.release_memory) {
    nmap_free_mem();
  }

	return 0;
}

static int nmap_fetchfile_sub(char *filename_returned, int bufferlen, const char *file);

/* Search for a file in the standard data file locations. The result is stored
   in filename_returned, which must point to an allocated buffer of at least
   bufferlen bytes. Returns true iff the search should be considered finished
   (i.e., the caller shouldn't try to search anywhere else for the file).

   Options like --servicedb and --versiondb set explicit locations for
   individual data files. If any of these were used those locations are checked
   first, and no other locations are checked.

   After that, the following directories are searched in order. First an
   NMAP_UPDATE_CHANNEL subdirectory is checked in all of them, then they are all
   tried again directly.
    * --datadir
    * $NMAPDIR
    * [Non-Windows only] ~/.nmap
    * [Windows only] ...\Users\<user>\AppData\Roaming\nmap
    * The directory containing the nmap binary
    * [Non-Windows only] The directory containing the nmap binary plus
      "/../share/nmap"
    * NMAPDATADIR */
int nmap_fetchfile(char *filename_returned, int bufferlen, const char *file) {
  const char *UPDATES_PREFIX = "updates/" NMAP_UPDATE_CHANNEL "/";
  std::map<std::string, std::string>::iterator iter;
  char buf[BUFSIZ];
  int res;

  // Check the map of requested data file names.
  iter = o.requested_data_files.find(file);
  if (iter != o.requested_data_files.end()) {
    Strncpy(filename_returned, iter->second.c_str(), bufferlen);
    // If a special file name was requested, we must not return any other file
    // name. Return a positive result even if the file doesn't exist or is not
    // readable. It is the caller's responsibility to report the error if the
    // file can't be accessed.
    res = file_is_readable(filename_returned);
    return res != 0 ? res : 1;
  }

  // Try updates directory first.
  Strncpy(buf, UPDATES_PREFIX, sizeof(buf));
  Strncpy(buf + strlen(UPDATES_PREFIX), file, sizeof(buf) - strlen(UPDATES_PREFIX));
  res = nmap_fetchfile_sub(filename_returned, bufferlen, buf);

  if (!res)
    res = nmap_fetchfile_sub(filename_returned, bufferlen, file);

  return res;
}


/* Returns true if the two given filenames refer to the same file. (Have the
   same device and inode number.) */
static bool same_file(const char *filename_a, const char *filename_b) {
  struct stat stat_a, stat_b;

  if (stat(filename_a, &stat_a) == -1)
    return false;
  if (stat(filename_b, &stat_b) == -1)
    return false;

  return stat_a.st_dev == stat_b.st_dev && stat_a.st_ino == stat_b.st_ino;
}

static int nmap_fetchfile_userdir_uid(char *buf, size_t buflen, const char *file, int uid) {
  struct passwd *pw;
  int res;

  pw = getpwuid(uid);
  if (pw == NULL)
    return 0;
  res = Snprintf(buf, buflen, "%s/.nmap/%s", pw->pw_dir, file);
  if (res <= 0 || (size_t) res >= buflen)
    return 0;

  return file_is_readable(buf);
}

static int nmap_fetchfile_userdir(char *buf, size_t buflen, const char *file) {
  int res;

  res = nmap_fetchfile_userdir_uid(buf, buflen, file, getuid());
  if (res != 0)
    return res;

  if (getuid() != geteuid()) {
    res = nmap_fetchfile_userdir_uid(buf, buflen, file, geteuid());
    if (res != 0)
      return res;
  }

  return 0;
}

static char *executable_dir(const char *argv0) {
  char *path, *dir;

  path = executable_path(argv0);
  if (path == NULL)
    return NULL;
  dir = path_get_dirname(path);
  free(path);

  return dir;
}

static int nmap_fetchfile_sub(char *filename_returned, int bufferlen, const char *file) {
  char *dirptr;
  int res;
  int foundsomething = 0;
  char dot_buffer[512];
  static int warningcount = 0;

  if (o.datadir) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", o.datadir, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = file_is_readable(filename_returned);
    }
  }

  if (!foundsomething && (dirptr = getenv("NMAPDIR"))) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", dirptr, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = file_is_readable(filename_returned);
    }
  }

  if (!foundsomething)
    foundsomething = nmap_fetchfile_userdir(filename_returned, bufferlen, file);

  const char *argv0;
  char *dir;

  argv0 = get_program_name();
  assert(argv0 != NULL);
  dir = executable_dir(argv0);

  if (dir != NULL) {
    if (!foundsomething) { /* Try the nMap directory */
      res = Snprintf(filename_returned, bufferlen, "%s/%s", dir, file);
      if (res > 0 && res < bufferlen) {
        foundsomething = file_is_readable(filename_returned);
      }
    }
#ifndef WIN32
    if (!foundsomething) {
      res = Snprintf(filename_returned, bufferlen, "%s/../share/nmap/%s", dir, file);
      if (res > 0 && res < bufferlen) {
        foundsomething = file_is_readable(filename_returned);
      }
    }
#endif
    free(dir);
  }

  if (!foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", NMAPDATADIR, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = file_is_readable(filename_returned);
    }
  }

  if (foundsomething && (*filename_returned != '.')) {
    res = Snprintf(dot_buffer, sizeof(dot_buffer), "./%s", file);
    if (res > 0 && res < bufferlen) {
      if (file_is_readable(dot_buffer) && !same_file(filename_returned, dot_buffer)) {
#ifdef WIN32
        if (warningcount++ < 1 && o.debugging)
#else
        if (warningcount++ < 1)
#endif
          error("Warning: File %s exists, but Nmap is using %s for security and consistency reasons.  set NMAPDIR=. to give priority to files in your local directory (may affect the other data files too).", dot_buffer, filename_returned);
      }
    }
  }

  if (foundsomething && o.debugging > 1)
    //log_write(LOG_PLAIN, "Fetchfile found %s\n", filename_returned);
	printf("Fetchfile found %s\n", filename_returned);

  return foundsomething;

}