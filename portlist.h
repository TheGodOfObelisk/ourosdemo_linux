#ifndef PORTLIST_H
#define PORTLIST_H

#include "base.h"//it is so strange that 
				 //target.h cannot identify PortList without it
#include "portreasons.h"
#include <vector>
/* port states */
#define PORT_UNKNOWN 0
#define PORT_CLOSED 1
#define PORT_OPEN 2
#define PORT_FILTERED 3
#define PORT_TESTING 4
#define PORT_FRESH 5
#define PORT_UNFILTERED 6
#define PORT_OPENFILTERED 7 /* Like udp/fin/xmas/null/ipproto scan with no response */
#define PORT_CLOSEDFILTERED 8 /* Idle scan */
#define PORT_HIGHEST_STATE 9 /* ***IMPORTANT -- BUMP THIS UP WHEN STATES ARE
                                ADDED *** */

#define TCPANDUDPANDSCTP IPPROTO_MAX
#define UDPANDSCTP (IPPROTO_MAX + 1)

enum serviceprobestate {
  PROBESTATE_INITIAL=1, // No probes started yet
  PROBESTATE_NULLPROBE, // Is working on the NULL Probe
  PROBESTATE_MATCHINGPROBES, // Is doing matching probe(s)
  PROBESTATE_NONMATCHINGPROBES, // The above failed, is checking nonmatches
  PROBESTATE_FINISHED_HARDMATCHED, // Yay!  Found a match
  PROBESTATE_FINISHED_SOFTMATCHED, // Well, a soft match anyway
  PROBESTATE_FINISHED_NOMATCH, // D'oh!  Failed to find the service.
  PROBESTATE_FINISHED_TCPWRAPPED, // We think the port is blocked via tcpwrappers
  PROBESTATE_EXCLUDED, // The port has been excluded from the scan
  PROBESTATE_INCOMPLETE // failed to complete (error, host timeout, etc.)
};

enum service_detection_type { SERVICE_DETECTION_TABLE, SERVICE_DETECTION_PROBED };

enum service_tunnel_type { SERVICE_TUNNEL_NONE, SERVICE_TUNNEL_SSL };

// Move some popular TCP ports to the beginning of the portlist, because
// that can speed up certain scans.  You should have already done any port
// randomization, this should prevent the ports from always coming out in the
// same order.
void random_port_cheat(u16 *ports, int portcount);

const char *statenum2str(int state);

struct serviceDeductions {
  serviceDeductions();
  void populateFullVersionString(char *buf, size_t n) const;

  char *name; // will be NULL if can't determine
  // Confidence is a number from 0 (least confident) to 10 (most
  // confident) expressing how accurate the service detection is
  // likely to be.
  int name_confidence;
  // Any of these 6 can be NULL if we weren't able to determine it
  char *product;
  char *version;
  char *extrainfo;
  char *hostname;
  char *ostype;
  char *devicetype;
  std::vector<char *> cpe;
  // SERVICE_TUNNEL_NONE or SERVICE_TUNNEL_SSL
  enum service_tunnel_type service_tunnel;
  // if we should give the user a service fingerprint to submit, here it is.  Otherwise NULL.
  char *service_fp;
  enum service_detection_type dtype; // definition above
};
class Port {
 friend class PortList;

 public:
  Port();
  void freeService(bool del_service);
  void getNmapServiceName(char *namebuf, int buflen) const;

  u16 portno;
  u8 proto;
  u8 state;
  state_reason_t reason;

 private:
  /* This is allocated only on demand by PortList::setServiceProbeResults
     to save memory for the many closed or filtered ports that don't need it. */
  serviceDeductions *service;
};



/* Needed enums to address some arrays. This values
 * should never be used directly. Use INPROTO2PORTLISTPROTO macro */
enum portlist_proto {	// PortList Protocols
  PORTLIST_PROTO_TCP	= 0,
  PORTLIST_PROTO_UDP	= 1,
  PORTLIST_PROTO_SCTP	= 2,
  PORTLIST_PROTO_IP	    = 3,
  PORTLIST_PROTO_MAX	= 4
};



class PortList{
public:
	PortList();
	~PortList();
 /* Set ports that will be scanned for each protocol. This function
   * must be called before any PortList object will be created. */
  static void initializePortMap(int protocol, u16 *ports, int portcount);
  /* Free memory used by port_map. It should be done somewhere before quitting*/
  static void freePortMap();

  void setDefaultPortState(u8 protocol, int state);
  void setPortState(u16 portno, u8 protocol, int state);
  int getPortState(u16 portno, u8 protocol);
  int forgetPort(u16 portno, u8 protocol);
  bool portIsDefault(u16 portno, u8 protocol);
  /* Saves an identification string for the target containing these
     ports (an IP address might be a good example, but set what you
     want).  Only used when printing new port updates.  Optional.  A
     copy is made. */
  void setIdStr(const char *id);
  /* A function for iterating through the ports.  Give NULL for the
   first "afterthisport".  Then supply the most recent returned port
   for each subsequent call.  When no more matching ports remain, NULL
   will be returned.  To restrict returned ports to just one protocol,
   specify IPPROTO_TCP, IPPROTO_UDP or UPPROTO_SCTP for
   allowed_protocol. A TCPANDUDPANDSCTP for allowed_protocol matches
   either. A 0 for allowed_state matches all possible states. This
   function returns ports in numeric order from lowest to highest,
   except that if you ask for TCP, UDP & SCTP, all TCP ports will be
   returned before we start returning UDP and finally SCTP ports */
  Port *nextPort(const Port *cur, Port *next,
                 int allowed_protocol, int allowed_state);

  int setStateReason(u16 portno, u8 proto, reason_t reason, u8 ttl, const struct sockaddr_storage *ip_addr);

  int numscriptresults; /* Total number of scripts which produced output */

  /* Get number of ports in this state. This a sum for protocols. */
  int getStateCounts(int state) const;
  /* Get number of ports in this state for requested protocol. */
  int getStateCounts(int protocol, int state) const;

  // sname should be NULL if sres is not
  // PROBESTATE_FINISHED_MATCHED. product,version, and/or extrainfo
  // will be NULL if unavailable. Note that this function makes its
  // own copy of sname and product/version/extrainfo.  This function
  // also takes care of truncating the version strings to a
  // 'reasonable' length if necessary, and cleaning up any unprintable
  // chars. (these tests are to avoid annoying DOS (or other) attacks
  // by malicious services).  The fingerprint should be NULL unless
  // one is available and the user should submit it.  tunnel must be
  // SERVICE_TUNNEL_NONE (normal) or SERVICE_TUNNEL_SSL (means ssl was
  // detected and we tried to tunnel through it ).
  void setServiceProbeResults(u16 portno, int protocol,
                              enum serviceprobestate sres, const char *sname,
                              enum service_tunnel_type tunnel, const char *product,
                              const char *version, const char *hostname,
                              const char *ostype, const char *devicetype,
                              const char *extrainfo,
                              const std::vector<const char *> *cpe,
                              const char *fingerprint);

  // pass in an allocated struct serviceDeductions (don't worry about initializing, and
  // you don't have to free any internal ptrs.  See the serviceDeductions definition for
  // the fields that are populated.  Returns 0 if at least a name is available.
  void getServiceDeductions(u16 portno, int protocol, struct serviceDeductions *sd) const;

  /* Cycles through the 0 or more "ignored" ports which should be
   consolidated for Nmap output.  They are returned sorted by the
   number of ports in the state, starting with the most common.  It
   should first be called with PORT_UNKNOWN to obtain the most popular
   ignored state (if any).  Then call with that state to get the next
   most popular one.  Returns the state if there is one, but returns
   PORT_UNKNOWN if there are no (more) states which qualify for
   consolidation */
  int nextIgnoredState(int prevstate);

  /* Returns true if a state should be ignored (consolidated), false otherwise */
  bool isIgnoredState(int state);

  int numIgnoredStates();
  int numIgnoredPorts();
  int numPorts() const;
  bool hasOpenPorts() const;

  /* Returns true if service scan is done and portno is found to be tcpwrapped, false otherwise */
  bool isTCPwrapped(u16 portno) const;

 private:
  void mapPort(u16 *portno, u8 *protocol) const;
  /* Get Port structure from PortList structure.*/
  const Port *lookupPort(u16 portno, u8 protocol) const;
  Port *createPort(u16 portno, u8 protocol);
  /* Set Port structure to PortList structure.*/
  void  setPortEntry(u16 portno, u8 protocol, Port *port);

  /* A string identifying the system these ports are on.  Just used for
     printing open ports, if it is set with setIdStr() */
  char *idstr;
  /* Number of ports in each state per each protocol. */
  int state_counts_proto[PORTLIST_PROTO_MAX][PORT_HIGHEST_STATE];
  Port **port_list[PORTLIST_PROTO_MAX];
 protected:
  /* Maps port_number to index in port_list array.
   * Only functions: getPortEntry, setPortEntry, initializePortMap and
   * nextPort should access this structure directly. */
  static u16 *port_map[PORTLIST_PROTO_MAX];
  static u16 *port_map_rev[PORTLIST_PROTO_MAX];
  /* Number of allocated elements in port_list per each protocol. */
  static int port_list_count[PORTLIST_PROTO_MAX];
  Port default_port_state[PORTLIST_PROTO_MAX];

};

#endif