#include "targets.h"
#include "scanops.h"
#include "xml.h"
#include "errorhandle.h"
#include "tcpip.h"
#include "util.h"
#include "timing.h"
#include "scan_engine.h"
#include <stdlib.h>
#include <assert.h>

extern ScanOps o;

/* Conducts an ARP ping sweep of the given hosts to determine which ones
   are up on a local ethernet network */
static void arpping(Target *hostbatch[], int num_hosts) {
  // First I change hostbatch into a std::vector<Target *>, which is what ultra_scan
  // takes.  I remove hosts that cannot be ARP scanned (such as localhost)
  std::vector<Target *> targets;
  int targetno;
  targets.reserve(num_hosts);

  for (targetno = 0; targetno < num_hosts; targetno++) {
    initialize_timeout_info(&hostbatch[targetno]->to);
    // Default timout should be much lower for arp
    hostbatch[targetno]->to.timeout = MAX(o.minRttTimeout(), MIN(o.initialRttTimeout(), INITIAL_ARP_RTT_TIMEOUT)) * 1000;
    if (!hostbatch[targetno]->SrcMACAddress()) {
      bool islocal = islocalhost(hostbatch[targetno]->TargetSockAddr());
      if (islocal) {
        //log_write(LOG_STDOUT|LOG_NORMAL,
        //        "ARP ping: Considering %s UP because it is a local IP, despite no MAC address for device %s\n",
        //        hostbatch[targetno]->NameIP(), hostbatch[targetno]->deviceName());
        printf("ARP ping: Considering %s UP because it is a local IP, despite no MAC address for device %s\n",
                  hostbatch[targetno]->NameIP(), hostbatch[targetno]->deviceName());   
        hostbatch[targetno]->flags = HOST_UP;
      } else {
        //log_write(LOG_STDOUT|LOG_NORMAL,
        //        "ARP ping: Considering %s DOWN because no MAC address found for device %s.\n",
        //        hostbatch[targetno]->NameIP(),
        //        hostbatch[targetno]->deviceName());
        printf("ARP ping: Considering %s DOWN because no MAC address found for device %s.\n",
                  hostbatch[targetno]->NameIP(),
                  hostbatch[targetno]->deviceName());
        hostbatch[targetno]->flags = HOST_DOWN;
      }
      continue;
    }
    targets.push_back(hostbatch[targetno]);
  }
  if (!targets.empty()) {
    if (targets[0]->af() == AF_INET)
      ultra_scan(targets, NULL, PING_SCAN_ARP);
    else
      ultra_scan(targets, NULL, PING_SCAN_ND);
  }
  return;
}

/* Lookahead is the number of hosts that can be
   checked (such as ping scanned) in advance.  Randomize causes each
   group of up to lookahead hosts to be internally shuffled around.
   The target_expressions array MUST REMAIN VALID IN MEMORY as long as
   this class instance is used -- the array is NOT copied.
 */
HostGroupState::HostGroupState(int lookahead, int rnd, int argc, const char **argv) {
  assert(lookahead > 0);
  this->argc = argc;
  this->argv = argv;
  hostbatch = (Target **) safe_zalloc(sizeof(Target *) * lookahead);
  defer_buffer = std::list<Target *>();
  undeferred = std::list<Target *>();
  max_batch_sz = lookahead;
  current_batch_sz = 0;
  next_batch_no = 0;
  randomize = rnd;
}


HostGroupState::~HostGroupState() {
  free(hostbatch);
}

void HostGroupState::undefer() {
  this->undeferred.splice(this->undeferred.end(), this->defer_buffer);
}

/* Add a <target> element to the XML stating that a target specification was
   ignored. This can be because of, for example, a DNS resolution failure, or a
   syntax error. */
static void log_bogus_target(const char *expr) {
  xml_open_start_tag("target");
  xml_attribute("specification", "%s", expr);
  xml_attribute("status", "skipped");
  xml_attribute("reason", "invalid");
  xml_close_empty_tag();
  xml_newline();
}

/* Is the host passed as Target to be excluded? Much of this logic had
   to be rewritten from wam's original code to allow for the objects */
static int hostInExclude(struct sockaddr *checksock, size_t checksocklen,
                  const addrset *exclude_group) {
  if (exclude_group == NULL)
    return 0;

  if (checksock == NULL)
    return 0;

  if (addrset_contains(exclude_group,checksock))
    return 1;
  return 0;
}

/* Returns a newly allocated Target with the given address. Handles all the
   details like setting the Target's address and next hop. */
static Target *setup_target(const HostGroupState *hs,
                            const struct sockaddr_storage *ss, size_t sslen,
                            int pingtype) {
  struct route_nfo rnfo;
  Target *t;

  t = new Target();

  t->setTargetSockAddr(ss, sslen);

  // Special handling for the resolved address (for example whatever
  // scanme.nmap.org resolves to in scanme.nmap.org/24).
  if (hs->current_group.is_resolved_address(ss)) {
    if (hs->current_group.get_namedhost())
      t->setTargetName(hs->current_group.get_resolved_name());
    t->unscanned_addrs = hs->current_group.get_unscanned_addrs();
  }

  // We figure out the source IP/device IFF
  // 1) We are r00t AND
  // 2) We are doing tcp or udp pingscan OR
  // 3) We are doing a raw-mode portscan or osscan or traceroute OR
  // 4) We are on windows and doing ICMP ping
  if (o.isr00t &&
      ((pingtype & (PINGTYPE_TCP|PINGTYPE_UDP|PINGTYPE_SCTP_INIT|PINGTYPE_PROTO|PINGTYPE_ARP)) || o.RawScan()
#ifdef WIN32
       || (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))
#endif // WIN32
      )) {
    if (!nmap_route_dst(ss, &rnfo)) {
      log_bogus_target(inet_ntop_ez(ss, sslen));
      error("%s: failed to determine route to %s", __func__, t->NameIP());
      goto bail;
    }
    if (rnfo.direct_connect) {
      t->setDirectlyConnected(true);
    } else {
      t->setDirectlyConnected(false);
      t->setNextHop(&rnfo.nexthop, sizeof(rnfo.nexthop));
    }
    t->setIfType(rnfo.ii.device_type);
    if (rnfo.ii.device_type == devt_ethernet) {
      if (o.spoofMACAddress())
        t->setSrcMACAddress(o.spoofMACAddress());
      else
        t->setSrcMACAddress(rnfo.ii.mac);
    }
#ifdef WIN32
    else if (g_has_npcap_loopback && rnfo.ii.device_type == devt_loopback) {
      if (o.spoofMACAddress())
        t->setSrcMACAddress(o.spoofMACAddress());
      else
        t->setSrcMACAddress(rnfo.ii.mac);
      t->setNextHopMACAddress(t->SrcMACAddress());
    }
#endif
    t->setSourceSockAddr(&rnfo.srcaddr, sizeof(rnfo.srcaddr));
    if (hs->current_batch_sz == 0) // Because later ones can have different src addy and be cut off group
      o.decoys[o.decoyturn] = t->source();
    t->setDeviceNames(rnfo.ii.devname, rnfo.ii.devfullname);
    t->setMTU(rnfo.ii.mtu);
    // printf("Target %s %s directly connected, goes through local iface %s, which %s ethernet\n", t->NameIP(), t->directlyConnected()? "IS" : "IS NOT", t->deviceName(), (t->ifType() == devt_ethernet)? "IS" : "IS NOT");
  }

  return t;

bail:
  delete t;
  return NULL;
}

static Target *next_target(HostGroupState *hs, const addrset *exclude_group,
  struct scan_lists *ports, int pingtype) {
  struct sockaddr_storage ss;
  size_t sslen;
  Target *t;

  // First handle targets deferred in the last batch.
  if (!hs->undeferred.empty()) {
    t = hs->undeferred.front();
    hs->undeferred.pop_front();
    return t;
  }

tryagain:

  if (hs->current_group.get_next_host(&ss, &sslen) != 0) {//1
    const char *expr;
    // We are going to have to pop in another expression. 
    for (;;) {
      expr = hs->next_expression();//2
      if (expr == NULL)
        // That's the last of them.
        return NULL;
      if (hs->current_group.parse_expr(expr, o.af()) == 0)//3
        break;
      else
        log_bogus_target(expr);
    }
    goto tryagain;
  }

  assert(ss.ss_family == o.af());

  // If we are resuming from a previous scan, we have already finished scanning
  // up to o.resume_ip. 
  if (ss.ss_family == AF_INET && o.resume_ip.s_addr) {
    if (o.resume_ip.s_addr == ((struct sockaddr_in *) &ss)->sin_addr.s_addr)
      // We will continue starting with the next IP.
      o.resume_ip.s_addr = 0;
    goto tryagain;
  }

  // Check exclude list.
  if (hostInExclude((struct sockaddr *) &ss, sslen, exclude_group))
    goto tryagain;

  t = setup_target(hs, &ss, sslen, pingtype);
  if (t == NULL)
    goto tryagain;

  return t;
}

static void hoststructfry(Target *hostbatch[], int nelem) {
  genfry((unsigned char *)hostbatch, sizeof(Target *), nelem);
  return;
}

static void massping(Target *hostbatch[], int num_hosts, struct scan_lists *ports) {
  static struct timeout_info group_to = { 0, 0, 0 };
  static char prev_device_name[16] = "";
  const char *device_name;
  std::vector<Target *> targets;
  int i;

  /* Get the name of the interface used to send to this group. We assume the
     device used to send to the first target is used to send to all of them. */
  device_name = NULL;
  if (num_hosts > 0)
    device_name = hostbatch[0]->deviceName();
  if (device_name == NULL)
    device_name = "";

  /* group_to is a static variable that keeps track of group timeout values
     between invocations of this function. We reuse timeouts as long as this
     invocation uses the same device as the previous one. Otherwise we
     reinitialize the timeouts. */
  if (group_to.srtt == 0 || group_to.rttvar == 0 || group_to.timeout == 0
    || strcmp(prev_device_name, device_name) != 0) {
    initialize_timeout_info(&group_to);
    Strncpy(prev_device_name, device_name, sizeof(prev_device_name));
  }

  for (i = 0; i < num_hosts; i++) {
    initialize_timeout_info(&hostbatch[i]->to);
    targets.push_back(hostbatch[i]);
  }

  ultra_scan(targets, ports, PING_SCAN, &group_to);
}

static void refresh_hostbatch(HostGroupState *hs, const addrset *exclude_group,
  struct scan_lists *ports, int pingtype) {
  int i;
  bool arpping_done = false;
  struct timeval now;

  hs->current_batch_sz = hs->next_batch_no = 0;
  hs->undefer();
  while (hs->current_batch_sz < hs->max_batch_sz) {
    Target *t;

    t = next_target(hs, exclude_group, ports, pingtype);
    if (t == NULL)
      break;

    // Does this target need to go in a separate host group? 
    if (target_needs_new_hostgroup(hs->hostbatch, hs->current_batch_sz, t)) {
      if (hs->defer(t))
        continue;
      else
        break;
    }

    o.decoys[o.decoyturn] = t->source();
    hs->hostbatch[hs->current_batch_sz++] = t;
  }
  if (hs->current_batch_sz == 0)
    return;

  // OK, now we have our complete batch of entries.  The next step is to
  // randomize them (if requested) 
  if (hs->randomize) {
    hoststructfry(hs->hostbatch, hs->current_batch_sz);
  }

  // First I'll do the ARP ping if all of the machines in the group are
  // directly connected over ethernet.  I may need the MAC addresses
  // later anyway.
  if (hs->hostbatch[0]->ifType() == devt_ethernet &&
      hs->hostbatch[0]->af() == AF_INET &&
      hs->hostbatch[0]->directlyConnected() &&
      o.sendpref != PACKET_SEND_IP_STRONG &&
      (pingtype == PINGTYPE_ARP || o.implicitARPPing)) {
    arpping(hs->hostbatch, hs->current_batch_sz);
    arpping_done = true;
  }
/*
  // No other interface types are supported by ND ping except devt_ethernet
  // at the moment.
  if (hs->hostbatch[0]->ifType() == devt_ethernet &&
      hs->hostbatch[0]->af() == AF_INET6 &&
      hs->hostbatch[0]->directlyConnected() &&
      o.sendpref != PACKET_SEND_IP_STRONG &&
      (pingtype == PINGTYPE_ARP || o.implicitARPPing)) {
    arpping(hs->hostbatch, hs->current_batch_sz);
    arpping_done = true;
  }
*/
//we don't need v6
  gettimeofday(&now, NULL);
  if ((o.sendpref & PACKET_SEND_ETH) &&
      hs->hostbatch[0]->ifType() == devt_ethernet) {
    for (i=0; i < hs->current_batch_sz; i++) {
      if (!(hs->hostbatch[i]->flags & HOST_DOWN) &&
          !hs->hostbatch[i]->timedOut(&now)) {
        if (!setTargetNextHopMAC(hs->hostbatch[i])) {
          fatal("%s: Failed to determine dst MAC address for target %s",
              __func__, hs->hostbatch[i]->NameIP());
        }
      }
    }
  }

  // Then we do the mass ping (if required - IP-level pings)
  if ((pingtype == PINGTYPE_NONE && !arpping_done) || hs->hostbatch[0]->ifType() == devt_loopback) {
    for (i=0; i < hs->current_batch_sz; i++) {
      if (!hs->hostbatch[i]->timedOut(&now)) {
        initialize_timeout_info(&hs->hostbatch[i]->to);
        hs->hostbatch[i]->flags |= HOST_UP; //hostbatch[i].up = 1;
        if (pingtype == PINGTYPE_NONE && !arpping_done)
          hs->hostbatch[i]->reason.reason_id = ER_USER;
        else
          hs->hostbatch[i]->reason.reason_id = ER_LOCALHOST;
      }
    }
  } else if (!arpping_done) {
    massping(hs->hostbatch, hs->current_batch_sz, ports);
  }

  // if (!o.noresolve)
  //   nmap_mass_rdns(hs->hostbatch, hs->current_batch_sz);
  // I am sure that we do not need rdns
}

Target *nexthost(HostGroupState *hs, const addrset *exclude_group,
                 struct scan_lists *ports, int pingtype) {
  if (hs->next_batch_no >= hs->current_batch_sz)
    refresh_hostbatch(hs, exclude_group, ports, pingtype);
  if (hs->next_batch_no >= hs->current_batch_sz)
    return NULL;

  return hs->hostbatch[hs->next_batch_no++];
}

const char *HostGroupState::next_expression() {
  if (o.max_ips_to_scan == 0 || o.numhosts_scanned + this->current_batch_sz < o.max_ips_to_scan) {
    const char *expr;
    expr = grab_next_host_spec(o.inputfd, o.generate_random_ips, this->argc, this->argv);
    if (expr != NULL)
      return expr;
  }
/*
#ifndef NOLUA
  // Add any new NSE discovered targets to the scan queue
  static char buf[1024];

  NewTargets *new_targets = NewTargets::get();
  if (o.script && new_targets != NULL) {
    if (new_targets->get_queued() > 0) {
      std::string expr_string;
      expr_string = new_targets->read().c_str();
      if (o.debugging > 3) {
        log_write(LOG_PLAIN,
                  "New targets in the scanned cache: %ld, pending ones: %ld.\n",
                  new_targets->get_scanned(), new_targets->get_queued());
      }
      if (!expr_string.empty()) {
        Strncpy(buf, expr_string.c_str(), sizeof(buf));
        return buf;
      }
    }
  }
#endif
*/
//it seems useless, we discarded it in win version
  return NULL;
}

/* Returns true iff this target is incompatible with the other hosts in the host
   group. This happens when:
     1. it uses a different interface, or
     2. it uses a different source address, or
     3. it is directly connected when the other hosts are not, or vice versa, or
     4. it has the same IP address as another target already in the group.
   These restrictions only apply for raw scans, including host discovery. */
bool target_needs_new_hostgroup(Target **targets, int targets_sz, const Target *target) {
  int i = 0;

  /* We've just started a new hostgroup, so any target is acceptable. */
  if (targets_sz == 0)
    return false;

  /* There are no restrictions on non-root scans. */
  if (!(o.isr00t && target->deviceName() != NULL))
    return false;

  /* Different address family? */
  if (targets[0]->af() != target->af())
    return true;

  /* Different interface name? */
  if (targets[0]->deviceName() != NULL &&
      target->deviceName() != NULL &&
      strcmp(targets[0]->deviceName(), target->deviceName()) != 0) {
    return true;
  }

  /* Different source address? */
  if (sockaddr_storage_cmp(targets[0]->SourceSockAddr(), target->SourceSockAddr()) != 0)
    return true;

  /* Different direct connectedness? */
  if (targets[0]->directlyConnected() != target->directlyConnected())
    return true;

  /* Is there already a target with this same IP address? ultra_scan doesn't
     cope with that, because it uses IP addresses to look up targets from
     replies. What happens is one target gets the replies for all probes
     referring to the same IP address. */
  for (i = 0; i < targets_sz; i++) {
    if (sockaddr_storage_cmp(targets[i]->TargetSockAddr(), target->TargetSockAddr()) == 0)
      return true;
  }

  return false;
}

/* Returns true iff the defer buffer is not yet full. */
bool HostGroupState::defer(Target *t) {
  this->defer_buffer.push_back(t);
  return this->defer_buffer.size() < HostGroupState::DEFER_LIMIT;
}

/* Returns the last host obtained by nexthost.  It will be given again the next
   time you call nexthost(). */
void returnhost(HostGroupState *hs) {
  assert(hs->next_batch_no > 0);
  hs->next_batch_no--;
}