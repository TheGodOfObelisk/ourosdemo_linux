#include "scanops.h"
#include "base.h"
#include "errorhandle.h"
#include <unistd.h>		//
#include <sys/types.h>//these two are used to handle geteuid()
#include <assert.h>

ScanOps::ScanOps(){
	datadir = NULL;
	xsl_stylesheet = NULL;
	Initialize();
}

ScanOps::~ScanOps(){
  	if (xsl_stylesheet) {
    	free(xsl_stylesheet);
    	xsl_stylesheet = NULL;
  	}

  	if (reference_FPs) {
    	delete reference_FPs;
    	reference_FPs = NULL;
  	}

  	if (dns_servers) {
    	free(dns_servers);
    	dns_servers = NULL;
  	}
  	if (extra_payload) {
    	free(extra_payload);
    	extra_payload = NULL;
  	}
  	if (ipoptions) {
    	free(ipoptions);
    	ipoptions = NULL;
  	}
  	if (portlist) {
    	free(portlist);
    	portlist = NULL;
  	}
  	if (exclude_portlist) {
    	free(exclude_portlist);
    	exclude_portlist = NULL;
  	}
  	//it is related to rdns, useless
  	/*
  	if (proxy_chain) {
    	nsock_proxychain_delete(proxy_chain);
    	proxy_chain = NULL;
  	}
  	*/
  	if (exclude_spec) {
    	free(exclude_spec);
    	exclude_spec = NULL;
  	}
  	if (idleProxy) {
    	free(idleProxy);
    	idleProxy = NULL;
  	}
  	if (datadir) {
    	free(datadir);
    	datadir = NULL;
  	}	
}

void ScanOps::Initialize(){
  	setaf(AF_INET);//set to ipv4
  	//attention! It needs environment variable of NMAP
  	//we need to handle it in that we are not using windows
  	//maybe have to change the parameter
    //if we are not in root mode...
#if defined WIN32 || defined __amigaos__
  	isr00t = 1;
#else
  	//if (getenv("NMAP_PRIVILEGED"))
		if(getenv("MY_ENV"))
		{
    	isr00t = 1;
		}
  	else if (getenv("NMAP_UNPRIVILEGED"))
    	isr00t = 0;
  	else
    	isr00t = !(geteuid());
 #endif
   	//isr00t = 1;
  	have_pcap = true;
  	// debugging = 0;
		debugging = 0;//test
  	verbose = 0;
  	min_packet_send_rate = 0.0; /* Unset. */
  	max_packet_send_rate = 0.0; /* Unset. */
  	stats_interval = 0.0; /* Unset. */
  	randomize_hosts = false;
  	randomize_ports = true;
  	sendpref = PACKET_SEND_NOPREF;
  	spoofsource = false;
  	fastscan = false;
  	device[0] = '\0';
  	ping_group_sz = PING_GROUP_SZ;
  	nogcc = false;
  	generate_random_ips = false;
  	reference_FPs = NULL;
  	magic_port = 33000 + (get_random_uint() % 31000);
  	magic_port_set = false;
  	timing_level = 3;
  	max_parallelism = 0;
  	min_parallelism = 0;
  	max_os_tries = 5;
  	max_rtt_timeout = MAX_RTT_TIMEOUT;
  	min_rtt_timeout = MIN_RTT_TIMEOUT;
  	initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
  	max_retransmissions = MAX_RETRANSMISSIONS;
  	min_host_group_sz = 1;
  	max_host_group_sz = 100000; // don't want to be restrictive unless user sets
  	max_tcp_scan_delay = MAX_TCP_SCAN_DELAY;
  	max_udp_scan_delay = MAX_UDP_SCAN_DELAY;
  	max_sctp_scan_delay = MAX_SCTP_SCAN_DELAY;
  	max_ips_to_scan = 0;
  	extra_payload_length = 0;
  	extra_payload = NULL;
  	scan_delay = 0;
  	open_only = false;
  	scanflags = -1;
  	defeat_rst_ratelimit = false;
  	defeat_icmp_ratelimit = false;
  	resume_ip.s_addr = 0;
  	osscan_limit = false;
  	osscan_guess = false;
  	numdecoys = 0;
  	decoyturn = -1;
	  // osscan = false;
  	osscan = true;
  	servicescan = false;
  	override_excludeports = false;
  	version_intensity = 7;
  	pingtype = PINGTYPE_UNKNOWN;
  	listscan = ackscan = bouncescan = connectscan = 0;
  	nullscan = xmasscan = fragscan = synscan = windowscan = 0;
  	maimonscan = idlescan = finscan = udpscan = ipprotscan = 0;
  	noportscan = noresolve = false;
  	sctpinitscan = 0;
  	sctpcookieechoscan = 0;
  	append_output = false;
  	memset(logfd, 0, sizeof(FILE *) * LOG_NUM_FILES);
  	ttl = -1;
  	badsum = false;
  	nmap_stdout = stdout;
  	gettimeofday(&start_time, NULL);
  	pTrace = vTrace = false;
  	reason = false;
  	adler32 = false;
  	if (datadir) free(datadir);
  	datadir = NULL;
  	xsl_stylesheet_set = false;
  	if (xsl_stylesheet) free(xsl_stylesheet);
  	xsl_stylesheet = NULL;
  	spoof_mac_set = false;
  	mass_dns = true;
  	deprecated_xml_osclass = false;
  	always_resolve = false;
  	resolve_all = false;
  	dns_servers = NULL;
  	implicitARPPing = true;
  	numhosts_scanned = 0;
  	numhosts_up = 0;
  	numhosts_scanning = 0;
  	noninteractive = false;
  	current_scantype = STYPE_UNKNOWN;
  	ipoptions = NULL;
  	ipoptionslen = 0;
  	ipopt_firsthop = 0;
  	ipopt_lasthop  = 0;
  	release_memory = false;
  	topportlevel = -1;

  	memset(&sourcesock, 0, sizeof(sourcesock));
  	sourcesocklen = 0;
  	excludefd = NULL;
  	exclude_spec = NULL;
  	inputfd = NULL;
  	idleProxy = NULL;
  	portlist = NULL;
  	exclude_portlist = NULL;
  	//proxy_chain = NULL;
  	resuming = false;
}

int ScanOps::SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  if (sourcesocklen <= 0)
    return 1;
  assert(sourcesocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &sourcesock, sourcesocklen);
  if (ss_len)
    *ss_len = sourcesocklen;
  return 0;
}

/* Returns a const pointer to the source address if set, or NULL if unset. */
const struct sockaddr_storage *ScanOps::SourceSockAddr() const {
  if (sourcesock.ss_family == AF_UNSPEC)
    return NULL;
  else
    return &sourcesock;
}


bool ScanOps::SCTPScan() {
  return sctpinitscan|sctpcookieechoscan;
}

bool ScanOps::TCPScan() {
  return ackscan|bouncescan|connectscan|finscan|idlescan|maimonscan|nullscan|synscan|windowscan|xmasscan;
}

bool ScanOps::UDPScan() {
  return udpscan;
}

bool ScanOps::RawScan() {
  if (ackscan||finscan||idlescan||ipprotscan||maimonscan||nullscan||osscan||synscan||udpscan||windowscan||xmasscan||sctpinitscan||sctpcookieechoscan||traceroute)
    return true;
  if (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS|PINGTYPE_TCP_USE_ACK|PINGTYPE_UDP|PINGTYPE_SCTP_INIT))
    return true;
  /* A SYN scan will only generate raw packets if nmap is running as root.
     Otherwise, it becomes a connect scan. */
  if ((pingtype & PINGTYPE_TCP_USE_SYN) && isr00t)
    return true;

   return false;
}

// Number of seconds since getStartTime().  The current time is an
// optional argument to avoid an extra gettimeofday() call.
float ScanOps::TimeSinceStart(const struct timeval *now) {
  struct timeval tv;
  if (!now)
    gettimeofday(&tv, NULL);
  else tv = *now;

  return TIMEVAL_FSEC_SUBTRACT(tv, start_time);
}


/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void ScanOps::setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
}

int ScanOps::pf() {
  return (af() == AF_INET)? PF_INET : PF_INET6;
}

void ScanOps::setInitialRttTimeout(int rtt)
{
  if (rtt <= 0) fatal("%s: initial round trip time must be greater than 0", __func__);
  initial_rtt_timeout = rtt;
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt;
}

void ScanOps::setMaxRttTimeout(int rtt)
{
  if (rtt <= 0) fatal("%s: maximum round trip time must be greater than 0", __func__);
  max_rtt_timeout = rtt;
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt;
  if (rtt < initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void ScanOps::setMinRttTimeout(int rtt)
{
  if (rtt < 0) fatal("%s: minimum round trip time must be at least 0", __func__);
  min_rtt_timeout = rtt;
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;
  if (rtt > initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void ScanOps::setMaxRetransmissions(int max_retransmit)
{
    if (max_retransmit < 0)
        fatal("%s: must be positive", __func__);
    max_retransmissions = max_retransmit;
}

void ScanOps::ValidateOptions() {
        const char *privreq = "root privileges.";
#ifdef WIN32
        if (!have_pcap)
          privreq = "Npcap, but it seems to be missing.\n\
Npcap is available from http://www.npcap.org. The Npcap driver service must\n\
be started by an administrator before Npcap can be used. Running nmap.exe\n\
will open a UAC dialog where you can start the service if you have\n\
administrator privileges.";
#endif


  /* Insure that at least one scantype is selected */
  if (!noportscan && !(TCPScan() || UDPScan() || SCTPScan() || ipprotscan)) {
    if (isr00t)
      synscan++;
    else connectscan++;
    //    if (verbose) error("No TCP, UDP, SCTP or ICMP scantype specified, assuming %s scan. Use -sn if you really don't want to portscan (and just want to see what hosts are up).", synscan? "SYN Stealth" : "vanilla tcp connect()");
  }

  if (pingtype != PINGTYPE_NONE && spoofsource) {
    error("WARNING: If -S is being used to fake your source address, you may also have to use -e <interface> and -Pn .  If you are using it to specify your real source address, you can ignore this warning.");
  }

  if (pingtype != PINGTYPE_NONE && idlescan) {
    error("WARNING: Many people use -Pn w/Idlescan to prevent pings from their true IP.  On the other hand, timing info Nmap gains from pings can allow for faster, more reliable scans.");
    sleep(2); /* Give ppl a chance for ^C :) */
  }

 if (numdecoys > 1 && idlescan) {
    error("WARNING: Your decoys won't be used in the Idlescan portion of your scanning (although all packets sent to the target are spoofed anyway");
  }

 if (connectscan && spoofsource) {
    error("WARNING: -S will only affect the source address used in a connect() scan if you specify one of your own addresses.  Use -sS or another raw scan if you want to completely spoof your source address, but then you need to know what you're doing to obtain meaningful results.");
  }

 if ((pingtype & PINGTYPE_UDP) && (!isr00t)) {
   fatal("Sorry, UDP Ping (-PU) only works if you are root (because we need to read raw responses off the wire)");
 }

 if ((pingtype & PINGTYPE_SCTP_INIT) && (!isr00t)) {
   fatal("Sorry, SCTP INIT Ping (-PY) only works if you are root (because we need to read raw responses off the wire)");
  }

 if ((pingtype & PINGTYPE_PROTO) && (!isr00t)) {
   fatal("Sorry, IPProto Ping (-PO) only works if you are root (because we need to read raw responses off the wire)");
 }

 if (ipprotscan && (TCPScan() || UDPScan() || SCTPScan())) {
   fatal("Sorry, the IPProtoscan (-sO) must currently be used alone rather than combined with other scan types.");
 }

 if (noportscan && (TCPScan() || UDPScan() || SCTPScan() || ipprotscan)) {
   fatal("-sL and -sn (skip port scan) are not valid with any other scan types");
 }

 if (af() == AF_INET6 && (pingtype & (PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))) {
   fatal("ICMP Timestamp and Address Mask pings are only valid for IPv4.");
 }

 if (sendpref == PACKET_SEND_NOPREF) {
#ifdef WIN32
   sendpref = PACKET_SEND_ETH_STRONG;
#else
   sendpref = PACKET_SEND_IP_WEAK;
#endif
 }
/* We start with stuff users should not do if they are not root */
  if (!isr00t) {

    if (ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|synscan|udpscan|windowscan|xmasscan|sctpinitscan|sctpcookieechoscan) {
      fatal("You requested a scan type which requires %s", privreq);
    }

    if (numdecoys > 0) {
      fatal("Sorry, but decoys (-D) require %s", privreq);
    }

    if (fragscan) {
      fatal("Sorry, but fragscan requires %s", privreq);
    }

    if (osscan) {
      fatal("TCP/IP fingerprinting (for OS scan) requires %s", privreq);
    }
  }


  if (bouncescan && pingtype != PINGTYPE_NONE)
    // log_write(LOG_STDOUT, "Hint: if your bounce scan target hosts aren't reachable from here, remember to use -Pn so we don't try and ping them prior to the scan\n");
    printf("Hint: if your bounce scan target hosts aren't reachable from here, remember to use -Pn so we don't try and ping them prior to the scan\n");

  if (ackscan+bouncescan+connectscan+finscan+idlescan+maimonscan+nullscan+synscan+windowscan+xmasscan > 1)
    fatal("You specified more than one type of TCP scan.  Please choose only one of -sA, -b, -sT, -sF, -sI, -sM, -sN, -sS, -sW, and -sX");

  if (numdecoys > 0 && (bouncescan || connectscan)) {
    error("WARNING: Decoys are irrelevant to the bounce or connect scans");
  }

  if (fragscan && !(ackscan|finscan|maimonscan|nullscan|synscan|windowscan|xmasscan) && \
      !(pingtype&(PINGTYPE_ICMP_TS|PINGTYPE_TCP)) && !(fragscan == 8 && pingtype&PINGTYPE_ICMP_MASK) && \
      !(extra_payload_length + 8 > fragscan)) {
    fatal("Fragscan only works with TCP, ICMP Timestamp or ICMP Mask (mtu=8) ping types or ACK, FIN, Maimon, NULL, SYN, Window, and XMAS scan types");
  }

  if (osscan && bouncescan)
    error("Combining bounce scan with OS scan seems silly, but I will let you do whatever you want!");

#if !defined(LINUX) && !defined(OPENBSD) && !defined(FREEBSD) && !defined(NETBSD)
  if (fragscan) {
    error("Warning: Packet fragmentation selected on a host other than Linux, OpenBSD, FreeBSD, or NetBSD.  This may or may not work.");
  }
#endif

  if (osscan && noportscan) {
    fatal("WARNING: OS Scan is unreliable without a port scan.  You need to use a scan type along with it, such as -sS, -sT, -sF, etc instead of -sn");
  }

  if (osscan && ipprotscan) {
    error("WARNING: Disabling OS Scan (-O) as it is incompatible with the IPProto Scan (-sO)");
    osscan = false;
  }

  if (servicescan && ipprotscan) {
    error("WARNING: Disabling Service Scan (-sV) as it is incompatible with the IPProto Scan (-sO)");
    servicescan = false;
  }

  if (servicescan && noportscan)
    servicescan = false;

  if (defeat_rst_ratelimit && !synscan && !openOnly()) {
    fatal("Option --defeat-rst-ratelimit works only with a SYN scan (-sS)");
  }

  if (defeat_icmp_ratelimit && !udpscan) {
    fatal("Option --defeat-icmp-ratelimit works only with a UDP scan (-sU)");
  }

  if (resume_ip.s_addr && generate_random_ips)
    resume_ip.s_addr = 0;

  if (magic_port_set && connectscan) {
    error("WARNING: -g is incompatible with the default connect() scan (-sT).  Use a raw scan such as -sS if you want to set the source port.");
  }

  if (max_parallelism && min_parallelism && (min_parallelism > max_parallelism)) {
    fatal("--min-parallelism=%i must be less than or equal to --max-parallelism=%i",min_parallelism,max_parallelism);
  }

  if (min_packet_send_rate != 0.0 && max_packet_send_rate != 0.0 && min_packet_send_rate > max_packet_send_rate) {
    fatal("--min-rate=%g must be less than or equal to --max-rate=%g", min_packet_send_rate, max_packet_send_rate);
  }

  if (af() == AF_INET6 && (generate_random_ips||bouncescan||fragscan)) {
    fatal("Random targets, FTP bounce scan, and fragmentation are not supported with IPv6.");
  }

  if(ipoptions && osscan)
    error("WARNING: IP options are NOT used while OS scanning!");

// #ifndef NOLUA
//    Make sure nmap.registry.args is available (even if it's empty) 
//   if (!scriptargs)
//     scriptargs = strdup("");
// #endif
}

void ScanOps::setSpoofMACAddress(u8 *mac_data) {
  memcpy(spoof_mac, mac_data, 6);
  spoof_mac_set = true;
}
