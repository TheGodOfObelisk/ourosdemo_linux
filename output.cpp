#include "output.h"
#include "target.h"
#include "FingerPrintResults.h"
#include "xml.h"
#include "base.h"
#include "scanops.h"
#include "util.h"
#include "portreasons.h"
#include "MACLookup.h"
#include "protocols.h"
#include "ScanOutputTable.h"
#include "errorhandle.h"
#include <math.h>

extern ScanOps o;

/* A convenience wrapper around mergeFPs. */
const char *FingerPrintResultsIPv4::merge_fpr(const Target *currenths,
                             bool isGoodFP, bool wrapit) const {
  return mergeFPs(this->FPs, this->numFPs, isGoodFP, currenths->TargetSockAddr(),
                  currenths->distance,
                  currenths->distance_calculation_method,
                  currenths->MACAddress(), this->osscan_opentcpport,
                  this->osscan_closedtcpport, this->osscan_closedudpport,
                  wrapit);
}

/* Prints the beginning of a "finished" start tag, with time, timestr, and
   elapsed attributes. Leaves the start tag open so you can add more attributes.
   You have to close the tag with xml_close_empty_tag. */
void print_xml_finished_open(time_t timep, const struct timeval *tv) {
  char mytime[128];

  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);

  xml_open_start_tag("finished");
  xml_attribute("time", "%lu", (unsigned long) timep);
  xml_attribute("timestr", "%s", mytime);
  xml_attribute("elapsed", "%.2f", o.TimeSinceStart(tv));
  xml_attribute("summary",
    "Nmap done at %s; %u %s (%u %s up) scanned in %.2f seconds",
    mytime, o.numhosts_scanned,
    (o.numhosts_scanned == 1) ? "IP address" : "IP addresses",
    o.numhosts_up, (o.numhosts_up == 1) ? "host" : "hosts",
    o.TimeSinceStart(tv));
}

void print_xml_hosts() {
  xml_open_start_tag("hosts");
  xml_attribute("up", "%d", o.numhosts_up);
  xml_attribute("down", "%d", o.numhosts_scanned - o.numhosts_up);
  xml_attribute("total", "%d", o.numhosts_scanned);
  xml_close_empty_tag();
}

/* Writes a heading for a full scan report ("Nmap scan report for..."),
   including host status and DNS records. */
void write_host_header(Target *currenths) {
  if ((currenths->flags & HOST_UP) || o.verbose || o.always_resolve) {
    if (currenths->flags & HOST_UP) {
      // log_write(LOG_PLAIN, "Nmap scan report for %s\n", currenths->NameIP());
      printf("Nmap scan report for %s\n", currenths->NameIP());
    } else if (currenths->flags & HOST_DOWN) {
      //log_write(LOG_PLAIN, "Nmap scan report for %s [host down", currenths->NameIP());
      printf("Nmap scan report for %s [host down", currenths->NameIP());
      if (o.reason)
        // log_write(LOG_PLAIN, ", %s", target_reason_str(currenths));
        printf(", %s", target_reason_str(currenths));
      // log_write(LOG_PLAIN, "]\n");
      printf("]\n");
    }
  }
  write_host_status(currenths);
  if (currenths->TargetName() != NULL
      && !currenths->unscanned_addrs.empty()) {

    // log_write(LOG_PLAIN, "Other addresses for %s (not scanned):",
    //   currenths->TargetName());
    printf("Other addresses for %s (not scanned):",
      currenths->TargetName());
    for (std::list<struct sockaddr_storage>::const_iterator it = currenths->unscanned_addrs.begin(), end = currenths->unscanned_addrs.end();
        it != end; it++) {
      struct sockaddr_storage ss = *it;
      // log_write(LOG_PLAIN, " %s", inet_ntop_ez(&ss, sizeof(ss)));
    printf(" %s", inet_ntop_ez(&ss, sizeof(ss)));
    }
    // log_write(LOG_PLAIN, "\n");
    printf("\n");
  }
  /* Print reverse DNS if it differs. */
  if (currenths->TargetName() != NULL
      && currenths->HostName() != NULL && currenths->HostName()[0] != '\0'
      && strcmp(currenths->TargetName(), currenths->HostName()) != 0) {
    // log_write(LOG_PLAIN, "rDNS record for %s: %s\n",
    //   currenths->targetipstr(), currenths->HostName());
    printf("rDNS record for %s: %s\n",
      currenths->targetipstr(), currenths->HostName());
  }
}

/* Prints the MAC address if one was found for the target (generally
   this means that the target is directly connected on an ethernet
   network.  This only prints to human output -- XML is handled by a
   separate call ( print_MAC_XML_Info ) because it needs to be printed
   in a certain place to conform to DTD. */
void printmacinfo(Target *currenths) {
  const u8 *mac = currenths->MACAddress();
  char macascii[32];

  if (mac) {
    const char *macvendor = MACPrefix2Corp(mac);
    Snprintf(macascii, sizeof(macascii), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    // log_write(LOG_PLAIN, "MAC Address: %s (%s)\n", macascii,
    //           macvendor ? macvendor : "Unknown");
    printf("MAC Address: %s (%s)\n", macascii,
              macvendor ? macvendor : "Unknown");
  }
}

void printtimes(Target *currenths) {
  if (currenths->to.srtt != -1 || currenths->to.rttvar != -1) {
    if (o.debugging) {
      // log_write(LOG_STDOUT, "Final times for host: srtt: %d rttvar: %d  to: %d\n",
      //   currenths->to.srtt, currenths->to.rttvar, currenths->to.timeout);
      printf("Final times for host: srtt: %d rttvar: %d  to: %d\n",
        currenths->to.srtt, currenths->to.rttvar, currenths->to.timeout);
    }
    xml_open_start_tag("times");
    xml_attribute("srtt", "%d", currenths->to.srtt);
    xml_attribute("rttvar", "%d", currenths->to.rttvar);
    xml_attribute("to", "%d", currenths->to.timeout);
    xml_close_empty_tag();
    xml_newline();
  }
}

/* Prints the MAC address (if discovered) to XML output */
static void print_MAC_XML_Info(Target *currenths) {
  const u8 *mac = currenths->MACAddress();
  char macascii[32];

  if (mac) {
    const char *macvendor = MACPrefix2Corp(mac);
    Snprintf(macascii, sizeof(macascii), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    xml_open_start_tag("address");
    xml_attribute("addr", "%s", macascii);
    xml_attribute("addrtype", "mac");
    if (macvendor)
      xml_attribute("vendor", "%s", macvendor);
    xml_close_empty_tag();
    xml_newline();
  }
}

/* Helper function to write the status and address/hostname info of a host
   into the XML log */
static void write_xml_initial_hostinfo(Target *currenths,
                                       const char *status) {
  xml_open_start_tag("status");
  xml_attribute("state", "%s", status);
  xml_attribute("reason", "%s", reason_str(currenths->reason.reason_id, SINGULAR));
  xml_attribute("reason_ttl", "%d", currenths->reason.ttl);
  xml_close_empty_tag();
  xml_newline();
  xml_open_start_tag("address");
  xml_attribute("addr", "%s", currenths->targetipstr());
  xml_attribute("addrtype", "%s", (o.af() == AF_INET) ? "ipv4" : "ipv6");
  xml_close_empty_tag();
  xml_newline();
  print_MAC_XML_Info(currenths);
  /* Output a hostnames element whenever we have a name to write or the target
     is up. */
  if (currenths->TargetName() != NULL || *currenths->HostName() || strcmp(status, "up") == 0) {
    xml_start_tag("hostnames");
    xml_newline();
    if (currenths->TargetName() != NULL) {
      xml_open_start_tag("hostname");
      xml_attribute("name", "%s", currenths->TargetName());
      xml_attribute("type", "user");
      xml_close_empty_tag();
      xml_newline();
    }
    if (*currenths->HostName()) {
      xml_open_start_tag("hostname");
      xml_attribute("name", "%s", currenths->HostName());
      xml_attribute("type", "PTR");
      xml_close_empty_tag();
      xml_newline();
    }
    xml_end_tag();
    xml_newline();
  }
  // log_flush_all();
  //?
}

/* Convert a number to a string, keeping the given number of significant digits.
   The result is returned in a static buffer. */
static char *num_to_string_sigdigits(double d, int digits) {
  static char buf[32];
  int shift;
  int n;

  assert(digits >= 0);
  if (d == 0.0) {
    shift = -digits;
  } else {
    shift = (int) floor(log10(fabs(d))) - digits + 1;
    d = floor(d / pow(10.0, shift) + 0.5);
    d = d * pow(10.0, shift);
  }

  n = Snprintf(buf, sizeof(buf), "%.*f", MAX(0, -shift), d);
  assert(n > 0 && n < (int) sizeof(buf));

  return buf;
}

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to
   machine log. */
void write_host_status(Target *currenths) {
  if (o.listscan) {
    /* write "unknown" to machine and xml */
    // log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Unknown\n",
    //           currenths->targetipstr(), currenths->HostName());
    printf("Host: %s (%s)\tStatus: Unknown\n",
              currenths->targetipstr(), currenths->HostName());
    write_xml_initial_hostinfo(currenths, "unknown");
  } else if (currenths->weird_responses) {
    /* SMURF ADDRESS */
    /* Write xml "down" or "up" based on flags and the smurf info */
    write_xml_initial_hostinfo(currenths,
                               (currenths->
                                flags & HOST_UP) ? "up" : "down");
    xml_open_start_tag("smurf");
    xml_attribute("responses", "%d", currenths->weird_responses);
    xml_close_empty_tag();
    xml_newline();
    // log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Smurf (%d responses)\n",
    //           currenths->targetipstr(), currenths->HostName(),
    //           currenths->weird_responses);
    printf("Host: %s (%s)\tStatus: Smurf (%d responses)\n",
              currenths->targetipstr(), currenths->HostName(),
              currenths->weird_responses);

    if (o.noportscan) {
      // log_write(LOG_PLAIN, "Host seems to be a subnet broadcast address (returned %d extra pings).%s\n",
      //           currenths->weird_responses,
      //           (currenths->flags & HOST_UP) ? " Note -- the actual IP also responded." : "");
      printf("Host seems to be a subnet broadcast address (returned %d extra pings).%s\n",
                currenths->weird_responses,
                (currenths->flags & HOST_UP) ? " Note -- the actual IP also responded." : "");
    } else {
      // log_write(LOG_PLAIN, "Host seems to be a subnet broadcast address (returned %d extra pings). %s.\n",
      //           currenths->weird_responses,
      //           (currenths->flags & HOST_UP) ? " Still scanning it due to ping response from its own IP" : "Skipping host");
      printf("Host seems to be a subnet broadcast address (returned %d extra pings). %s.\n",
                currenths->weird_responses,
                (currenths->flags & HOST_UP) ? " Still scanning it due to ping response from its own IP" : "Skipping host");
    }
  } else {
    /* Ping scan / port scan. */

    write_xml_initial_hostinfo(currenths, (currenths->flags & HOST_UP) ? "up" : "down");
    if (currenths->flags & HOST_UP) {
      // log_write(LOG_PLAIN, "Host is up");
      printf("Host is up");
      if (o.reason)
        // log_write(LOG_PLAIN, ", %s", target_reason_str(currenths));
        printf(", %s", target_reason_str(currenths));
      if (o.reason && currenths->reason.ttl)
        // log_write(LOG_PLAIN, " ttl %d", currenths->reason.ttl);
        printf(" ttl %d", currenths->reason.ttl);
      if (currenths->to.srtt != -1)
        // log_write(LOG_PLAIN, " (%ss latency)",
        //           num_to_string_sigdigits(currenths->to.srtt / 1000000.0, 2));
        printf(" (%ss latency)",
                  num_to_string_sigdigits(currenths->to.srtt / 1000000.0, 2));
      // log_write(LOG_PLAIN, ".\n");
      printf(".\n");

      // log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Up\n",
      //           currenths->targetipstr(), currenths->HostName());
      printf("Host: %s (%s)\tStatus: Up\n",
                currenths->targetipstr(), currenths->HostName());
    } else if (currenths->flags & HOST_DOWN) {
      // log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Down\n",
      //           currenths->targetipstr(), currenths->HostName());
      printf("Host: %s (%s)\tStatus: Down\n",
                currenths->targetipstr(), currenths->HostName());
    }
  }
}

/* Remove all "\nSF:" from fingerprints */
static char *servicefp_sf_remove(const char *str) {
  char *temp = (char *) safe_malloc(strlen(str) + 1);
  char *dst = temp, *src = (char *) str;
  char *ampptr = 0;

  while (*src) {
    if (strncmp(src, "\nSF:", 4) == 0) {
      src += 4;
      continue;
    }
    /* Needed so "&something;" is not truncated midway */
    if (*src == '&') {
      ampptr = dst;
    } else if (*src == ';') {
      ampptr = 0;
    }
    *dst++ = *src++;
  }
  if (ampptr != 0) {
    *ampptr = '\0';
  } else {
    *dst = '\0';
  }
  return temp;
}

// Prints an XML <service> element for the information given in
// serviceDeduction.  This function should only be called if ether
// the service name or the service fingerprint is non-null.
static void print_xml_service(const struct serviceDeductions *sd) {
  xml_open_start_tag("service");

  xml_attribute("name", "%s", sd->name ? sd->name : "unknown");
  if (sd->product)
    xml_attribute("product", "%s", sd->product);
  if (sd->version)
    xml_attribute("version", "%s", sd->version);
  if (sd->extrainfo)
    xml_attribute("extrainfo", "%s", sd->extrainfo);
  if (sd->hostname)
    xml_attribute("hostname", "%s", sd->hostname);
  if (sd->ostype)
    xml_attribute("ostype", "%s", sd->ostype);
  if (sd->devicetype)
    xml_attribute("devicetype", "%s", sd->devicetype);
  if (sd->service_fp) {
    char *servicefp = servicefp_sf_remove(sd->service_fp);
    xml_attribute("servicefp", "%s", servicefp);
    free(servicefp);
  }

  if (sd->service_tunnel == SERVICE_TUNNEL_SSL)
    xml_attribute("tunnel", "ssl");
  xml_attribute("method", "%s", (sd->dtype == SERVICE_DETECTION_TABLE) ? "table" : "probed");
  xml_attribute("conf", "%i", sd->name_confidence);

  if (sd->cpe.empty()) {
    xml_close_empty_tag();
  } else {
    unsigned int i;

    xml_close_start_tag();
    for (i = 0; i < sd->cpe.size(); i++) {
      xml_start_tag("cpe");
      xml_write_escaped("%s", sd->cpe[i]);
      xml_end_tag();
    }
    xml_end_tag();
  }
}

/* Prints the familiar Nmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Grepable
   output and the XML output.  It is pretty ugly -- in particular I
   should write helper functions to handle the table creation */
void printportoutput(Target *currenths, PortList *plist,target_in_file *t) {
  char protocol[MAX_IPPROTOSTRLEN + 1];
  char portinfo[64];
  char grepvers[256];
  char *p;
  const char *state;
  char serviceinfo[64];
  int i;
  int first = 1;
  struct protoent *proto;
  Port *current;
  Port port;
  char hostname[1200];
  struct serviceDeductions sd;
  NmapOutputTable *Tbl = NULL;
  int portcol = -1;             // port or IP protocol #
  int statecol = -1;            // port/protocol state
  int servicecol = -1;          // service or protocol name
  int versioncol = -1;
  int reasoncol = -1;
  int colno = 0;
  unsigned int rowno;
  int numrows;
  int numignoredports = plist->numIgnoredPorts();
  int numports = plist->numPorts();

  std::vector<const char *> saved_servicefps;

  if (o.noportscan)
    return;

  xml_start_tag("ports");
  int prevstate = PORT_UNKNOWN;
  int istate;

  while ((istate = plist->nextIgnoredState(prevstate)) != PORT_UNKNOWN) {
    xml_open_start_tag("extraports");
    xml_attribute("state", "%s", statenum2str(istate));
    xml_attribute("count", "%d", plist->getStateCounts(istate));
    xml_close_start_tag();
    xml_newline();
    print_xml_state_summary(plist, istate);
    xml_end_tag();
    xml_newline();
    prevstate = istate;
  }

  if (numignoredports == numports) {
    if (numignoredports == 0) {
      // log_write(LOG_PLAIN, "0 ports scanned on %s\n",
      //           currenths->NameIP(hostname, sizeof(hostname)));
      printf("0 ports scanned on %s\n",
                currenths->NameIP(hostname, sizeof(hostname)));
    } else {
      // log_write(LOG_PLAIN, "%s %d scanned %s on %s %s ",
      //           (numignoredports == 1) ? "The" : "All", numignoredports,
      //           (numignoredports == 1) ? "port" : "ports",
      //           currenths->NameIP(hostname, sizeof(hostname)),
      //           (numignoredports == 1) ? "is" : "are");
      printf("%s %d scanned %s on %s %s ",
                (numignoredports == 1) ? "The" : "All", numignoredports,
                (numignoredports == 1) ? "port" : "ports",
                currenths->NameIP(hostname, sizeof(hostname)),
                (numignoredports == 1) ? "is" : "are");
      if (plist->numIgnoredStates() == 1) {
        // log_write(LOG_PLAIN, "%s", statenum2str(plist->nextIgnoredState(PORT_UNKNOWN)));
        printf("%s", statenum2str(plist->nextIgnoredState(PORT_UNKNOWN)));
      } else {
        prevstate = PORT_UNKNOWN;
        while ((istate = plist->nextIgnoredState(prevstate)) != PORT_UNKNOWN) {
          if (prevstate != PORT_UNKNOWN)
            // log_write(LOG_PLAIN, " or ");
            printf(" or ");
          // log_write(LOG_PLAIN, "%s (%d)", statenum2str(istate),
          //           plist->getStateCounts(istate));
          printf("%s (%d)", statenum2str(istate),
                    plist->getStateCounts(istate));
          prevstate = istate;
        }
      }
      if (o.reason)
        print_state_summary(plist, STATE_REASON_EMPTY);
      // log_write(LOG_PLAIN, "\n");
      printf("\n");
    }

    // log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Up",
    //           currenths->targetipstr(), currenths->HostName());
    printf("Host: %s (%s)\tStatus: Up",
              currenths->targetipstr(), currenths->HostName());
    xml_end_tag(); /* ports */
    xml_newline();
    return;
  }

  if (o.verbose > 1 || o.debugging) {
    time_t tm_secs, tm_sece;
    struct tm *tm;
    char tbufs[128];
    tm_secs = currenths->StartTime();
    tm_sece = currenths->EndTime();
    tm = localtime(&tm_secs);
    if (strftime(tbufs, sizeof(tbufs), "%Y-%m-%d %H:%M:%S %Z", tm) <= 0)
      fatal("Unable to properly format host start time");

    // log_write(LOG_PLAIN, "Scanned at %s for %lds\n",
    //           tbufs, (long) (tm_sece - tm_secs));
    printf("Scanned at %s for %lds\n",
              tbufs, (long) (tm_sece - tm_secs));
  }
  // log_write(LOG_MACHINE, "Host: %s (%s)", currenths->targetipstr(),
  //           currenths->HostName());
  printf("Host: %s (%s)", currenths->targetipstr(),
            currenths->HostName());

  /* Show line like:
     Not shown: 3995 closed ports, 514 filtered ports
     if appropriate (note that states are reverse-sorted by # of ports) */
  prevstate = PORT_UNKNOWN;
  while ((istate = plist->nextIgnoredState(prevstate)) != PORT_UNKNOWN) {
    if (prevstate == PORT_UNKNOWN)
      // log_write(LOG_PLAIN, "Not shown: ");
      printf("Not shown: ");
    else
      // log_write(LOG_PLAIN, ", ");
      printf(", ");
    char desc[32];
    if (o.ipprotscan)
      Snprintf(desc, sizeof(desc),
               (plist->getStateCounts(istate) ==
                1) ? "protocol" : "protocols");
    else
      Snprintf(desc, sizeof(desc),
               (plist->getStateCounts(istate) == 1) ? "port" : "ports");
    // log_write(LOG_PLAIN, "%d %s %s", plist->getStateCounts(istate),
    //           statenum2str(istate), desc);
    printf("%d %s %s", plist->getStateCounts(istate),
              statenum2str(istate), desc);
    prevstate = istate;
  }

  // log_write(LOG_PLAIN, "\n");
  printf("\n");

  if (o.reason)
    print_state_summary(plist, STATE_REASON_FULL);

  /* OK, now it is time to deal with the service table ... */
  colno = 0;
  portcol = colno++;
  statecol = colno++;
  servicecol = colno++;
  if (o.reason)
    reasoncol = colno++;
  if (o.servicescan)
    versioncol = colno++;

  numrows = numports - numignoredports;

// #ifndef NOLUA
//   int scriptrows = 0;
//   if (plist->numscriptresults > 0)
//     scriptrows = plist->numscriptresults;
//   numrows += scriptrows;
// #endif

  assert(numrows > 0);
  numrows++; // The header counts as a row

  Tbl = new NmapOutputTable(numrows, colno);

  // Lets start with the headers
  if (o.ipprotscan)
    Tbl->addItem(0, portcol, false, "PROTOCOL", 8);
  else
    Tbl->addItem(0, portcol, false, "PORT", 4);
  Tbl->addItem(0, statecol, false, "STATE", 5);
  Tbl->addItem(0, servicecol, false, "SERVICE", 7);
  if (versioncol > 0)
    Tbl->addItem(0, versioncol, false, "VERSION", 7);
  if (reasoncol > 0)
    Tbl->addItem(0, reasoncol, false, "REASON", 6);

  // log_write(LOG_MACHINE, "\t%s: ", (o.ipprotscan) ? "Protocols" : "Ports");
  printf("\t%s: ", (o.ipprotscan) ? "Protocols" : "Ports");

  rowno = 1;
  if (o.ipprotscan) {
    current = NULL;
    while ((current = plist->nextPort(current, &port, IPPROTO_IP, 0)) != NULL) {
      if (!plist->isIgnoredState(current->state)) {
        if (!first)
          // log_write(LOG_MACHINE, ", ");
          printf(", ");
        else
          first = 0;
        if (o.reason) {
          if (current->reason.ttl)
            Tbl->addItemFormatted(rowno, reasoncol, false, "%s ttl %d",
                                port_reason_str(current->reason), current->reason.ttl);
          else
            Tbl->addItem(rowno, reasoncol, true, port_reason_str(current->reason));
        }
        state = statenum2str(current->state);
        proto = nmap_getprotbynum(current->portno);
        Snprintf(portinfo, sizeof(portinfo), "%s", proto ? proto->p_name : "unknown");
        Tbl->addItemFormatted(rowno, portcol, false, "%d", current->portno);
        Tbl->addItem(rowno, statecol, true, state);
        Tbl->addItem(rowno, servicecol, true, portinfo);
        // log_write(LOG_MACHINE, "%d/%s/%s/", current->portno, state,
        //           (proto) ? proto->p_name : "");
        printf("%d/%s/%s/", current->portno, state,
                  (proto) ? proto->p_name : "");
        xml_open_start_tag("port");
        xml_attribute("protocol", "ip");
        xml_attribute("portid", "%d", current->portno);
        xml_close_start_tag();
        xml_open_start_tag("state");
        xml_attribute("state", "%s", state);
        xml_attribute("reason", "%s", reason_str(current->reason.reason_id, SINGULAR));
        xml_attribute("reason_ttl", "%d", current->reason.ttl);
        if (current->reason.ip_addr.sockaddr.sa_family != AF_UNSPEC) {
          struct sockaddr_storage ss;
          memcpy(&ss, &current->reason.ip_addr, sizeof(current->reason.ip_addr));
          xml_attribute("reason_ip", "%s", inet_ntop_ez(&ss, sizeof(ss)));
        }
        xml_close_empty_tag();

        if (proto && proto->p_name && *proto->p_name) {
          xml_newline();
          xml_open_start_tag("service");
          xml_attribute("name", "%s", proto->p_name);
          xml_attribute("conf", "8");
          xml_attribute("method", "table");
          xml_close_empty_tag();
        }
        xml_end_tag(); /* port */
        xml_newline();
        rowno++;
      }
    }
  } else {
    char fullversion[160];

    current = NULL;
    while ((current = plist->nextPort(current, &port, TCPANDUDPANDSCTP, 0)) != NULL) {
      if (!plist->isIgnoredState(current->state)) {
        if (!first)
          // log_write(LOG_MACHINE, ", ");
          printf(", ");
        else
          first = 0;
        strcpy(protocol, IPPROTO2STR(current->proto));
        Snprintf(portinfo, sizeof(portinfo), "%d/%s", current->portno, protocol);
        state = statenum2str(current->state);
        plist->getServiceDeductions(current->portno, current->proto, &sd);
        if (sd.service_fp && saved_servicefps.size() <= 8)
          saved_servicefps.push_back(sd.service_fp);

        current->getNmapServiceName(serviceinfo, sizeof(serviceinfo));

        Tbl->addItem(rowno, portcol, true, portinfo);
        Tbl->addItem(rowno, statecol, false, state);
        Tbl->addItem(rowno, servicecol, true, serviceinfo);
        if (o.reason) {
          if (current->reason.ttl)
            Tbl->addItemFormatted(rowno, reasoncol, false, "%s ttl %d",
                                  port_reason_str(current->reason), current->reason.ttl);
          else
            Tbl->addItem(rowno, reasoncol, true, port_reason_str(current->reason));
        }

        sd.populateFullVersionString(fullversion, sizeof(fullversion));
        if (*fullversion && versioncol > 0)
          Tbl->addItem(rowno, versioncol, true, fullversion);

        // How should we escape illegal chars in grepable output?
        // Well, a reasonably clean way would be backslash escapes
        // such as \/ and \\ .  // But that makes it harder to pick
        // out fields with awk, cut, and such.  So I'm gonna use the
        // ugly hack (fitting to grepable output) of replacing the '/'
        // character with '|' in the version field.
        Strncpy(grepvers, fullversion, sizeof(grepvers) / sizeof(*grepvers));
        p = grepvers;
        while ((p = strchr(p, '/'))) {
          *p = '|';
          p++;
        }
        if (sd.name || sd.service_fp || sd.service_tunnel != SERVICE_TUNNEL_NONE) {
          p = serviceinfo;
          while ((p = strchr(p, '/'))) {
            *p = '|';
            p++;
          }
        }
        else {
          serviceinfo[0] = '\0';
        }
        // log_write(LOG_MACHINE, "%d/%s/%s//%s//%s/", current->portno,
        //           state, protocol, serviceinfo, grepvers);
        printf("%d/%s/%s//%s//%s/", current->portno,
                  state, protocol, serviceinfo, grepvers);
  	PortInfo portinfo_temp;
		portinfo_temp.portno = current->portno;
		portinfo_temp.state = state;
		portinfo_temp.protocol = protocol;
		portinfo_temp.serviceinfo = serviceinfo;
		t->PortInfoList.push_back(portinfo_temp);
        xml_open_start_tag("port");
        xml_attribute("protocol", "%s", protocol);
        xml_attribute("portid", "%d", current->portno);
        xml_close_start_tag();
        xml_open_start_tag("state");
        xml_attribute("state", "%s", state);
        xml_attribute("reason", "%s", reason_str(current->reason.reason_id, SINGULAR));
        xml_attribute("reason_ttl", "%d", current->reason.ttl);
        if (current->reason.ip_addr.sockaddr.sa_family != AF_UNSPEC) {
          struct sockaddr_storage ss;
          memcpy(&ss, &current->reason.ip_addr, sizeof(current->reason.ip_addr));
          xml_attribute("reason_ip", "%s", inet_ntop_ez(&ss, sizeof(ss)));
        }
        xml_close_empty_tag();

        if (sd.name || sd.service_fp || sd.service_tunnel != SERVICE_TUNNEL_NONE)
          print_xml_service(&sd);

        rowno++;
// #ifndef NOLUA
//         if (o.script) {
//           ScriptResults::const_iterator ssr_iter;
//           //Sort the results before outputting them on the screen
//           current->scriptResults.sort(scriptid_lessthan);
//           for (ssr_iter = current->scriptResults.begin();
//                ssr_iter != current->scriptResults.end(); ssr_iter++) {
//             ssr_iter->write_xml();

//             char *script_output = formatScriptOutput((*ssr_iter));
//             if (script_output != NULL) {
//               Tbl->addItem(rowno, 0, true, true, script_output);
//               free(script_output);
//             }
//             rowno++;
//           }

//         }
// #endif

        xml_end_tag(); /* port */
        xml_newline();
      }
    }

  }
  /*  log_write(LOG_PLAIN,"\n"); */
  /* Grepable output supports only one ignored state. */
  if (plist->numIgnoredStates() == 1) {
    istate = plist->nextIgnoredState(PORT_UNKNOWN);
    if (plist->getStateCounts(istate) > 0)
      // log_write(LOG_MACHINE, "\tIgnored State: %s (%d)",
      //           statenum2str(istate), plist->getStateCounts(istate));
      printf("\tIgnored State: %s (%d)",
                statenum2str(istate), plist->getStateCounts(istate));
  }
  xml_end_tag(); /* ports */
  xml_newline();

  if (o.defeat_rst_ratelimit && o.TCPScan() && plist->getStateCounts(PORT_FILTERED) > 0) {
    // log_write(LOG_PLAIN, "Some closed ports may be reported as filtered due to --defeat-rst-ratelimit\n");
    printf("Some closed ports may be reported as filtered due to --defeat-rst-ratelimit\n");
  }

  // Now we write the table for the user
  // log_write(LOG_PLAIN, "%s", Tbl->printableTable(NULL));
  printf("%s", Tbl->printableTable(NULL));
  delete Tbl;

  // There may be service fingerprints I would like the user to submit
  if (saved_servicefps.size() > 0) {
    int numfps = saved_servicefps.size();
    // log_write(LOG_PLAIN, "%d service%s unrecognized despite returning data."
    //           " If you know the service/version, please submit the following"
    //           " fingerprint%s at"
    //           " https://nmap.org/cgi-bin/submit.cgi?new-service :\n",
    //           numfps, (numfps > 1) ? "s" : "", (numfps > 1) ? "s" : "");
    printf("%d service%s unrecognized despite returning data."
              " If you know the service/version, please submit the following"
              " fingerprint%s at"
              " https://nmap.org/cgi-bin/submit.cgi?new-service :\n",
              numfps, (numfps > 1) ? "s" : "", (numfps > 1) ? "s" : "");
    for (i = 0; i < numfps; i++) {
      if (numfps > 1)
        // log_write(LOG_PLAIN, "==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============\n");
        printf("==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============\n");
      // log_write(LOG_PLAIN, "%s\n", saved_servicefps[i]);
      printf("%s\n", saved_servicefps[i]);
    }
  }
  // log_flush_all();
}

static void write_xml_osclass(const OS_Classification *osclass, double accuracy) {
  xml_open_start_tag("osclass");
  xml_attribute("type", "%s", osclass->Device_Type);
  xml_attribute("vendor", "%s", osclass->OS_Vendor);
  xml_attribute("osfamily", "%s", osclass->OS_Family);
  // Because the OS_Generation field is optional.
  if (osclass->OS_Generation)
    xml_attribute("osgen", "%s", osclass->OS_Generation);
  xml_attribute("accuracy", "%d", (int) (accuracy * 100));
  if (osclass->cpe.empty()) {
    xml_close_empty_tag();
  } else {
    unsigned int i;

    xml_close_start_tag();
    for (i = 0; i < osclass->cpe.size(); i++) {
      xml_start_tag("cpe");
      xml_write_escaped("%s", osclass->cpe[i]);
      xml_end_tag();
    }
    xml_end_tag();
  }
  xml_newline();
}

/* Returns -1 if adding the entry is not possible because it would
   overflow.  Otherwise it returns the new number of entries.  Note
   that only unique entries are added.  Also note that *numentries is
   incremented if the candidate is added.  arrsize is the number of
   char * members that fit into arr */
static int addtochararrayifnew(const char *arr[], int *numentries, int arrsize,
                               const char *candidate) {
  int i;

  // First lets see if the member already exists
  for (i = 0; i < *numentries; i++) {
    if (strcmp(arr[i], candidate) == 0)
      return *numentries;
  }

  // Not already there... do we have room for a new one?
  if (*numentries >= arrsize)
    return -1;

  // OK, not already there and we have room, so we'll add it.
  arr[*numentries] = candidate;
  (*numentries)++;
  return *numentries;
}

/* guess is true if we should print guesses */
#define MAX_OS_CLASSMEMBERS 8
static void printosclassificationoutput(const struct
                                        OS_Classification_Results *OSR,
                                        bool guess) {
  int classno, cpeno, familyno;
  unsigned int i;
  int overflow = 0;             /* Whether we have too many devices to list */
  const char *types[MAX_OS_CLASSMEMBERS];
  const char *cpes[MAX_OS_CLASSMEMBERS];
  char fullfamily[MAX_OS_CLASSMEMBERS][128];    // "[vendor] [os family]"
  double familyaccuracy[MAX_OS_CLASSMEMBERS];   // highest accuracy for this fullfamily
  char familygenerations[MAX_OS_CLASSMEMBERS][96];      // example: "4.X|5.X|6.X"
  int numtypes = 0, numcpes = 0, numfamilies = 0;
  char tmpbuf[1024];

  for (i = 0; i < MAX_OS_CLASSMEMBERS; i++) {
    familygenerations[i][0] = '\0';
    familyaccuracy[i] = 0.0;
  }

  if (OSR->overall_results == OSSCAN_SUCCESS) {

    if (o.deprecated_xml_osclass) {
      for (classno = 0; classno < OSR->OSC_num_matches; classno++)
        write_xml_osclass(OSR->OSC[classno], OSR->OSC_Accuracy[classno]);
    }

    // Now to create the fodder for normal output
    for (classno = 0; classno < OSR->OSC_num_matches; classno++) {
      /* We have processed enough if any of the following are true */
      if ((!guess && classno >= OSR->OSC_num_perfect_matches) ||
          OSR->OSC_Accuracy[classno] <= OSR->OSC_Accuracy[0] - 0.1 ||
          (OSR->OSC_Accuracy[classno] < 1.0 && classno > 9))
        break;
      if (addtochararrayifnew(types, &numtypes, MAX_OS_CLASSMEMBERS,
                              OSR->OSC[classno]->Device_Type) == -1) {
        overflow = 1;
      }
      for (i = 0; i < OSR->OSC[classno]->cpe.size(); i++) {
        if (addtochararrayifnew(cpes, &numcpes, MAX_OS_CLASSMEMBERS,
                                OSR->OSC[classno]->cpe[i]) == -1) {
          overflow = 1;
        }
      }

      // If family and vendor names are the same, no point being redundant
      if (strcmp(OSR->OSC[classno]->OS_Vendor, OSR->OSC[classno]->OS_Family) == 0)
        Strncpy(tmpbuf, OSR->OSC[classno]->OS_Family, sizeof(tmpbuf));
      else
        Snprintf(tmpbuf, sizeof(tmpbuf), "%s %s", OSR->OSC[classno]->OS_Vendor, OSR->OSC[classno]->OS_Family);


      // Let's see if it is already in the array
      for (familyno = 0; familyno < numfamilies; familyno++) {
        if (strcmp(fullfamily[familyno], tmpbuf) == 0) {
          // got a match ... do we need to add the generation?
          if (OSR->OSC[classno]->OS_Generation
              && !strstr(familygenerations[familyno],
                         OSR->OSC[classno]->OS_Generation)) {
            int flen = strlen(familygenerations[familyno]);
            // We add it, preceded by | if something is already there
            if (flen + 2 + strlen(OSR->OSC[classno]->OS_Generation) >=
                sizeof(familygenerations[familyno]))
              fatal("buffer 0verfl0w of familygenerations");
            if (*familygenerations[familyno])
              strcat(familygenerations[familyno], "|");
            strncat(familygenerations[familyno],
                    OSR->OSC[classno]->OS_Generation,
                    sizeof(familygenerations[familyno]) - flen - 1);
          }
          break;
        }
      }

      if (familyno == numfamilies) {
        // Looks like the new family is not in the list yet.  Do we have room to add it?
        if (numfamilies >= MAX_OS_CLASSMEMBERS) {
          overflow = 1;
          break;
        }
        // Have space, time to add...
        Strncpy(fullfamily[numfamilies], tmpbuf, 128);
        if (OSR->OSC[classno]->OS_Generation)
          Strncpy(familygenerations[numfamilies],
                  OSR->OSC[classno]->OS_Generation, 48);
        familyaccuracy[numfamilies] = OSR->OSC_Accuracy[classno];
        numfamilies++;
      }
    }

    if (!overflow && numfamilies >= 1) {
      // log_write(LOG_PLAIN, "Device type: ");
      printf("Device type: ");
      for (classno = 0; classno < numtypes; classno++)
        // log_write(LOG_PLAIN, "%s%s", types[classno], (classno < numtypes - 1) ? "|" : "");
        printf("%s%s", types[classno], (classno < numtypes - 1) ? "|" : "");
      // log_write(LOG_PLAIN, "\nRunning%s: ", OSR->OSC_num_perfect_matches == 0 ? " (JUST GUESSING)" : "");
      printf("\nRunning%s: ", OSR->OSC_num_perfect_matches == 0 ? " (JUST GUESSING)" : "");
      for (familyno = 0; familyno < numfamilies; familyno++) {
        if (familyno > 0)
          // log_write(LOG_PLAIN, ", ");
          printf(", ");
        // log_write(LOG_PLAIN, "%s", fullfamily[familyno]);
        printf("%s", fullfamily[familyno]);
        if (*familygenerations[familyno])
          // log_write(LOG_PLAIN, " %s", familygenerations[familyno]);
          printf(" %s", familygenerations[familyno]);
        if (familyno >= OSR->OSC_num_perfect_matches)
          // log_write(LOG_PLAIN, " (%.f%%)",
          //           floor(familyaccuracy[familyno] * 100));
          printf(" (%.f%%)",
                    floor(familyaccuracy[familyno] * 100));
      }
      // log_write(LOG_PLAIN, "\n");
      printf("\n");

      if (numcpes > 0) {
        // log_write(LOG_PLAIN, "OS CPE:");
        printf("OS CPE:");
        for (cpeno = 0; cpeno < numcpes; cpeno++)
          // log_write(LOG_PLAIN, " %s", cpes[cpeno]);
          printf(" %s", cpes[cpeno]);
        // log_write(LOG_PLAIN, "\n");
        printf("\n");
      }
    }
  }
  // log_flush_all();
  return;
}

static void write_merged_fpr(const FingerPrintResults *FPR,
                             const Target *currenths,
                             bool isGoodFP, bool wrapit) {
  // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
  //           "TCP/IP fingerprint:\n%s\n",
  //           FPR->merge_fpr(currenths, isGoodFP, wrapit));
  printf("TCP/IP fingerprint:\n%s\n",
            FPR->merge_fpr(currenths, isGoodFP, wrapit));


  /* Added code here to print fingerprint to XML file any time it would be
     printed to any other output format  */
  xml_open_start_tag("osfingerprint");
  xml_attribute("fingerprint", "%s", FPR->merge_fpr(currenths, isGoodFP, wrapit));
  xml_close_empty_tag();
  xml_newline();
}

static void write_xml_osmatch(const FingerMatch *match, double accuracy,int index,target_in_file *t) {
  xml_open_start_tag("osmatch");
  xml_attribute("name", "%s", match->OS_name);
  xml_attribute("accuracy", "%d", (int) (accuracy * 100));
  xml_attribute("line", "%d", match->line);
  if(0 == index)
		t->os_name = match->OS_name;
  /* When o.deprecated_xml_osclass is true, we don't write osclass elements as
     children of osmatch but rather as unrelated siblings. */
  if (match->OS_class.empty() || o.deprecated_xml_osclass) {
    xml_close_empty_tag();
  } else {
    unsigned int i;

    xml_close_start_tag();
    xml_newline();
      for (i = 0; i < match->OS_class.size(); i++){
		if(0 == index && i==0){
			t->device_type += match->OS_class[i].Device_Type;
			t->device_type += " ";
		}
      write_xml_osclass(&match->OS_class[i], accuracy);
	}
    xml_end_tag();
  }
  xml_newline();
}

/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed).*/
void printosscanoutput(Target *currenths,target_in_file *t) {
  int i;
  char numlst[512];             /* For creating lists of numbers */
  char *p;                      /* Used in manipulating numlst above */
  FingerPrintResults *FPR;
  int osscan_flag;

  if (!(osscan_flag = currenths->osscanPerformed()))
    return;

  if (currenths->FPR == NULL)
    return;
  FPR = currenths->FPR;

  xml_start_tag("os");
  if (FPR->osscan_opentcpport > 0) {
    xml_open_start_tag("portused");
    xml_attribute("state", "open");
    xml_attribute("proto", "tcp");
    xml_attribute("portid", "%d", FPR->osscan_opentcpport);
    xml_close_empty_tag();
    xml_newline();
  }
  if (FPR->osscan_closedtcpport > 0) {
    xml_open_start_tag("portused");
    xml_attribute("state", "closed");
    xml_attribute("proto", "tcp");
    xml_attribute("portid", "%d", FPR->osscan_closedtcpport);
    xml_close_empty_tag();
    xml_newline();
  }
  if (FPR->osscan_closedudpport > 0) {
    xml_open_start_tag("portused");
    xml_attribute("state", "closed");
    xml_attribute("proto", "udp");
    xml_attribute("portid", "%d", FPR->osscan_closedudpport);
    xml_close_empty_tag();
    xml_newline();
  }

  if (osscan_flag == OS_PERF_UNREL &&
      !(FPR->overall_results == OSSCAN_TOOMANYMATCHES ||
        (FPR->num_perfect_matches > 8 && !o.debugging)))
    // log_write(LOG_PLAIN, "Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port\n");
    printf("Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port\n");

  // If the FP can't be submitted anyway, might as well make a guess.
  const char *reason = FPR->OmitSubmissionFP();
  printosclassificationoutput(FPR->getOSClassification(), o.osscan_guess || reason);

  if (FPR->overall_results == OSSCAN_SUCCESS &&
      (FPR->num_perfect_matches <= 8 || o.debugging)) {
    /* Success, not too many perfect matches. */
    if (FPR->num_perfect_matches > 0) {
      /* Some perfect matches. */
      for (i = 0; i < FPR->num_perfect_matches; i++)
       write_xml_osmatch(FPR->matches[i], FPR->accuracy[i],i,t);

      // log_write(LOG_MACHINE, "\tOS: %s", FPR->matches[0]->OS_name);
      printf("\tOS: %s", FPR->matches[0]->OS_name);
      for (i = 1; i < FPR->num_perfect_matches; i++)
        // log_write(LOG_MACHINE, "|%s", FPR->matches[i]->OS_name);
        printf("|%s", FPR->matches[i]->OS_name);

      unsigned short numprints = FPR->matches[0]->numprints;
      // log_write(LOG_PLAIN, "OS details: %s", FPR->matches[0]->OS_name);
      printf("OS details: %s", FPR->matches[0]->OS_name);
      for (i = 1; i < FPR->num_perfect_matches; i++) {
        numprints = MIN(numprints, FPR->matches[i]->numprints);
        // log_write(LOG_PLAIN, ", %s", FPR->matches[i]->OS_name);
        printf(", %s", FPR->matches[i]->OS_name);
      }
      // log_write(LOG_PLAIN, "\n");
      printf("\n");

      /* Suggest submission of an already-matching IPv6 fingerprint with
       * decreasing probability as numprints increases, and never if the group
       * has 5 or more prints or if the print is unsuitable. */
      bool suggest_submission = currenths->af() == AF_INET6 && reason == NULL && rand() % 5 >= numprints;
      if (suggest_submission)
        // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
        //     "Nmap needs more fingerprint submissions of this type. Please submit via https://nmap.org/submit/\n");
        printf("Nmap needs more fingerprint submissions of this type. Please submit via https://nmap.org/submit/\n");
      if (suggest_submission || o.debugging || o.verbose > 1)
        write_merged_fpr(FPR, currenths, reason == NULL, true);
    } else {
      /* No perfect matches. */
      if ((o.verbose > 1 || o.debugging) && reason)
        // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
        //           "OS fingerprint not ideal because: %s\n", reason);
        printf("OS fingerprint not ideal because: %s\n", reason);

      for (i = 0; i < 10 && i < FPR->num_matches && FPR->accuracy[i] > FPR->accuracy[0] - 0.10; i++)
                write_xml_osmatch(FPR->matches[i], FPR->accuracy[i],i,t);

      if ((o.osscan_guess || reason) && FPR->num_matches > 0) {
        /* Print the best guesses available */
        // log_write(LOG_PLAIN, "Aggressive OS guesses: %s (%.f%%)",
        //           FPR->matches[0]->OS_name, floor(FPR->accuracy[0] * 100));
        printf("Aggressive OS guesses: %s (%.f%%)",
                  FPR->matches[0]->OS_name, floor(FPR->accuracy[0] * 100));
        for (i = 1; i < 10 && FPR->num_matches > i && FPR->accuracy[i] > FPR->accuracy[0] - 0.10; i++)
          // log_write(LOG_PLAIN, ", %s (%.f%%)", FPR->matches[i]->OS_name, floor(FPR->accuracy[i] * 100));
          printf(", %s (%.f%%)", FPR->matches[i]->OS_name, floor(FPR->accuracy[i] * 100));

        // log_write(LOG_PLAIN, "\n");
        printf("\n");
      }

      if (!reason) {
        // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
        //           "No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).\n");
        printf("No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).\n");
        write_merged_fpr(FPR, currenths, true, true);
      } else {
        // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
        //           "No exact OS matches for host (test conditions non-ideal).\n");
        printf("No exact OS matches for host (test conditions non-ideal).\n");
        if (o.verbose > 1 || o.debugging)
          write_merged_fpr(FPR, currenths, false, false);
      }
    }
  } else if (FPR->overall_results == OSSCAN_NOMATCHES) {
    /* No matches at all. */
    if (!reason) {
      // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
      //           "No OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).\n");
      printf("No OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).\n");
      write_merged_fpr(FPR, currenths, true, true);
    } else {
      // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
      //           "OS fingerprint not ideal because: %s\n", reason);
      // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
      //           "No OS matches for host\n");
      printf("OS fingerprint not ideal because: %s\n", reason);
      printf("No OS matches for host\n");
      if (o.debugging || o.verbose > 1)
        write_merged_fpr(FPR, currenths, false, false);
    }
  } else if (FPR->overall_results == OSSCAN_TOOMANYMATCHES
             || (FPR->num_perfect_matches > 8 && !o.debugging)) {
    /* Too many perfect matches. */
    // log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
    //           "Too many fingerprints match this host to give specific OS details\n");
    printf("Too many fingerprints match this host to give specific OS details\n");
    if (o.debugging || o.verbose > 1)
      write_merged_fpr(FPR, currenths, false, false);
  } else {
    assert(0);
  }

  xml_end_tag(); /* os */
  xml_newline();

  if (currenths->seq.lastboot) {
    char tmbuf[128];
    struct timeval tv;
    double uptime;
    strncpy(tmbuf, ctime(&currenths->seq.lastboot), sizeof(tmbuf));
    chomp(tmbuf);
    gettimeofday(&tv, NULL);
    uptime = difftime(tv.tv_sec, currenths->seq.lastboot);
    if (o.verbose)
      // log_write(LOG_PLAIN, "Uptime guess: %.3f days (since %s)\n",
      //           uptime / 86400,
      //           tmbuf);
      printf("Uptime guess: %.3f days (since %s)\n",
                uptime / 86400,
                tmbuf);
    xml_open_start_tag("uptime");
    xml_attribute("seconds", "%.0f", uptime);
    xml_attribute("lastboot", "%s", tmbuf);
    xml_close_empty_tag();
    xml_newline();
  }

  if (currenths->distance != -1) {
    // log_write(LOG_PLAIN, "Network Distance: %d hop%s\n",
    //           currenths->distance, (currenths->distance == 1) ? "" : "s");
    printf("Network Distance: %d hop%s\n",
              currenths->distance, (currenths->distance == 1) ? "" : "s");
    xml_open_start_tag("distance");
    xml_attribute("value", "%d", currenths->distance);
    xml_close_empty_tag();
    xml_newline();
  }

  if (currenths->seq.responses > 3) {
    p = numlst;
    for (i = 0; i < currenths->seq.responses; i++) {
      if (p - numlst > (int) (sizeof(numlst) - 15))
        fatal("STRANGE ERROR #3877 -- please report to fyodor@nmap.org\n");
      if (p != numlst)
        *p++ = ',';
      sprintf(p, "%X", currenths->seq.seqs[i]);
      while (*p)
        p++;
    }

    xml_open_start_tag("tcpsequence");
    xml_attribute("index", "%li", (long) currenths->seq.index);
    xml_attribute("difficulty", "%s", seqidx2difficultystr(currenths->seq.index));
    xml_attribute("values", "%s", numlst);
    xml_close_empty_tag();
    xml_newline();
    if (o.verbose)
      // log_write(LOG_PLAIN, "TCP Sequence Prediction: Difficulty=%d (%s)\n", currenths->seq.index, seqidx2difficultystr(currenths->seq.index));
      printf("TCP Sequence Prediction: Difficulty=%d (%s)\n", currenths->seq.index, seqidx2difficultystr(currenths->seq.index));

    // log_write(LOG_MACHINE, "\tSeq Index: %d", currenths->seq.index);
    printf("\tSeq Index: %d", currenths->seq.index);
  }

  if (currenths->seq.responses > 2) {
    p = numlst;
    for (i = 0; i < currenths->seq.responses; i++) {
      if (p - numlst > (int) (sizeof(numlst) - 15))
        fatal("STRANGE ERROR #3876 -- please report to fyodor@nmap.org\n");
      if (p != numlst)
        *p++ = ',';
      sprintf(p, "%hX", currenths->seq.ipids[i]);
      while (*p)
        p++;
    }
    xml_open_start_tag("ipidsequence");
    xml_attribute("class", "%s", ipidclass2ascii(currenths->seq.ipid_seqclass));
    xml_attribute("values", "%s", numlst);
    xml_close_empty_tag();
    xml_newline();
    if (o.verbose)
      // log_write(LOG_PLAIN, "IP ID Sequence Generation: %s\n",
      //           ipidclass2ascii(currenths->seq.ipid_seqclass));
      printf("IP ID Sequence Generation: %s\n",
                ipidclass2ascii(currenths->seq.ipid_seqclass));
    // log_write(LOG_MACHINE, "\tIP ID Seq: %s",
    //           ipidclass2ascii(currenths->seq.ipid_seqclass));
    printf("\tIP ID Seq: %s",
              ipidclass2ascii(currenths->seq.ipid_seqclass));

    p = numlst;
    for (i = 0; i < currenths->seq.responses; i++) {
      if (p - numlst > (int) (sizeof(numlst) - 15))
        fatal("STRANGE ERROR #3878 -- please report to fyodor@nmap.org\n");
      if (p != numlst)
        *p++ = ',';
      sprintf(p, "%X", currenths->seq.timestamps[i]);
      while (*p)
        p++;
    }

    xml_open_start_tag("tcptssequence");
    xml_attribute("class", "%s", tsseqclass2ascii(currenths->seq.ts_seqclass));
    if (currenths->seq.ts_seqclass != TS_SEQ_UNSUPPORTED) {
      xml_attribute("values", "%s", numlst);
    }
    xml_close_empty_tag();
    xml_newline();
  }
  // log_flush_all();
}