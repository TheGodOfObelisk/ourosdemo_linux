#ifndef MY_TARGET_H
#define MY_TARGET_H

#include "netutil.h"
#include "timing.h"
#include "osscan.h"
#include "FingerPrintResults.h"
#include "portlist.h"
#include "portreasons.h"
#include "scan_engine.h"

#include <list>

#define FQDN_LEN 254

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

class FingerPrintResults;//the same as the source code


struct host_timeout_nfo {
  unsigned long msecs_used; /* How many msecs has this Target used? */
  bool toclock_running; /* Is the clock running right now? */
  struct timeval toclock_start; /* When did the clock start? */
  time_t host_start, host_end; /* The absolute start and end for this host */
};

class Target{
public:
	Target();
	~Target();
  	/* Recycles the object by freeing internal objects and reinitializing
     to default state */
  	void Recycle();//don't have definition
   	/* Returns the address family of the destination address. */
  	int af() const;
  	/* Fills a sockaddr_storage with the AF_INET or AF_INET6 address
     information of the target.  This is a preferred way to get the
     address since it is portable for IPv6 hosts.  Returns 0 for
     success. ss_len must be provided.  It is not examined, but is set
     to the size of the sockaddr copied in. */
  	int TargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const;
  	const struct sockaddr_storage *TargetSockAddr() const;
	/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
	   to sockaddr_storage */
	void setTargetSockAddr(const struct sockaddr_storage *ss, size_t ss_len);
	// Returns IPv4 target host address or {0} if unavailable.
	struct in_addr v4host() const;
	const struct in_addr *v4hostip() const;
	const struct in6_addr *v6hostip() const;
	/* The source address used to reach the target */
	int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const;
	const struct sockaddr_storage *SourceSockAddr() const;
	/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
	   to sockaddr_storage */
	void setSourceSockAddr(const struct sockaddr_storage *ss, size_t ss_len);
  	struct sockaddr_storage source() const;
  	const struct in_addr *v4sourceip() const;
  	const struct in6_addr *v6sourceip() const;
  	/* The IPv4 or IPv6 literal string for the target host */
  	const char *targetipstr() const { return targetipstring; }
  	/* The IPv4 or IPv6 literal string for the source address */
  	const char *sourceipstr() const { return sourceipstring; }
  	/* Give the name from the last setHostName() call, which should be
   	the name obtained from reverse-resolution (PTR query) of the IP (v4
   	or v6).  If the name has not been set, or was set to NULL, an empty
   	string ("") is returned to make printing easier. */
  	const char *HostName() const { return hostname? hostname : "";  }
  	/* You can set to NULL to erase a name or if it failed to resolve -- or
     just don't call this if it fails to resolve.  The hostname is blown
     away when you setTargetSockAddr(), so make sure you do these in proper
     order
  	*/
  	void setHostName(const char *name);
  	/* Generates a printable string consisting of the host's IP
     address and hostname (if available).  Eg "www.insecure.org
     (64.71.184.53)" or "fe80::202:e3ff:fe14:1102".  The name is
     written into the buffer provided, which is also returned.  Results
     that do not fit in buflen will be truncated. */
  	const char *NameIP(char *buf, size_t buflen) const;
  	/* This next version returns a STATIC buffer -- so no concurrency */
  	const char *NameIP() const;

  	/* Give the name from the last setTargetName() call, which is the
   	name of the target given on the command line if it's a named
   	host. */
  	const char *TargetName() { return targetname; }
  	/* You can set to NULL to erase a name.  The targetname is blown
     	away when you setTargetSockAddr(), so make sure you do these in proper
     	order
  	*/
  	void setTargetName(const char *name);

  	/* If the host is directly connected on a network, set and retrieve
     that information here.  directlyConnected() will abort if it hasn't
     been set yet.  */
  	void setDirectlyConnected(bool connected);
  	bool directlyConnected() const;
  	int directlyConnectedOrUnset() const; /* 1-directly connected, 0-no, -1-we don't know*/

  	/* If the host is NOT directly connected, you can set the next hop
     value here. It is OK to pass in a sockaddr_in or sockaddr_in6
     casted to sockaddr_storage*/
  	void setNextHop(struct sockaddr_storage *next_hop, size_t next_hop_len);
  	/* Returns the next hop for sending packets to this host.  Returns true if
     next_hop was filled in.  It might be false, for example, if
     next_hop has never been set */
  	bool nextHop(struct sockaddr_storage *next_hop, size_t *next_hop_len);

  	void setMTU(int devmtu);
  	int MTU(void);

  	/* Sets the interface type to one of:
     devt_ethernet, devt_loopback, devt_p2p, devt_other
   	*/
  	void setIfType(devtype iftype) { interface_type = iftype; }
  	/* Returns -1 if it has not yet been set with setIfType() */
  	devtype ifType() { return interface_type; }
  	/* Starts the timeout clock for the host running (e.g. you are
     beginning a scan).  If you do not have the current time handy,
     you can pass in NULL.  When done, call stopTimeOutClock (it will
     also automatically be stopped of timedOut() returns true) */
  	void startTimeOutClock(const struct timeval *now);
  	/* The complement to startTimeOutClock. */
  	void stopTimeOutClock(const struct timeval *now);
  	/* Is the timeout clock currently running? */
  	bool timeOutClockRunning() { return htn.toclock_running; }
  	/* Returns whether the host is timedout.  If the timeoutclock is
     running, counts elapsed time for that.  Pass NULL if you don't have the
     current time handy.  You might as well also pass NULL if the
     clock is not running, as the func won't need the time. */
  	bool timedOut(const struct timeval *now);
  	/* Return time_t for the start and end time of this host */
  	time_t StartTime() { return htn.host_start; }
  	time_t EndTime() { return htn.host_end; }

  	/* Takes a 6-byte MAC address */
  	int setMACAddress(const u8 *addy);
  	int setSrcMACAddress(const u8 *addy);
  	int setNextHopMACAddress(const u8 *addy); // this should be the target's own MAC if directlyConnected()

  	/* Returns a pointer to 6-byte MAC address, or NULL if none is set */
  	const u8 *MACAddress() const;
  	const u8 *SrcMACAddress() const;
  	const u8 *NextHopMACAddress() const;

	/* Set the device names so that they can be returned by deviceName()
   	and deviceFullName().  The normal name may not include alias
   	qualifier, while the full name may include it (e.g. "eth1:1").  If
   	these are non-null, they will overwrite the stored version */
  	void setDeviceNames(const char *name, const char *fullname);
  	const char *deviceName() const;
  	const char *deviceFullName() const;

  	int osscanPerformed(void);
  	void osscanSetFlag(int flag);
  	
  	struct seq_info seq;
  	int distance;
  	enum dist_calc_method distance_calculation_method;
  	FingerPrintResults *FPR; // FP results get by the OS scan system.
  	PortList ports;

  	int weird_responses; /* echo responses from other addresses, Ie a network broadcast address */
  	unsigned int flags; /* HOST_UNKNOWN, HOST_UP, or HOST_DOWN. */
  	struct timeout_info to;//actually it is not a pointer
  	//timeout_info is declared in timing.h
  	char *hostname; // Null if unable to resolve or unset
  	char * targetname; // The name of the target host given on the command line if it is a named host

  	struct probespec traceroute_probespec;
  	//it seems useless
  	//std::list <TracerouteHop> traceroute_hops;

  	/* If the address for this target came from a DNS lookup, the list of
     resultant addresses (sometimes there are more than one) that were not scanned. */
  	std::list<struct sockaddr_storage> unscanned_addrs;//program will list the address unscanned

  	state_reason_t reason;

  	/* A probe that is known to receive a response. This is used to hold the
     current timing ping probe type during scanning. */
  	probespec pingprobe;
  	/* The state the port or protocol entered when the response to pingprobe was
     received. */
  	int pingprobe_state;


private:
  	void Initialize();
  	void FreeInternal(); // Free memory allocated inside this object
 	// Creates a "presentation" formatted string out of the target's IPv4/IPv6 address
  	void GenerateTargetIPString();
 	// Creates a "presentation" formatted string out of the source IPv4/IPv6 address.
  	void GenerateSourceIPString();
  	struct sockaddr_storage targetsock, sourcesock, nexthopsock;
  	size_t targetsocklen, sourcesocklen, nexthopsocklen;
  	int directly_connected; // -1 = unset; 0 = no; 1 = yes
  	char targetipstring[INET6_ADDRSTRLEN];
  	char sourceipstring[INET6_ADDRSTRLEN];
  	mutable char *nameIPBuf; /* for the NameIP(void) function to return */
  	u8 MACaddress[6], SrcMACaddress[6], NextHopMACaddress[6];
  	bool MACaddress_set, SrcMACaddress_set, NextHopMACaddress_set;
  	struct host_timeout_nfo htn;
  	devtype interface_type;
  	char devname[32];
  	char devfullname[32];
  	int mtu;
  	/* 0 (OS_NOTPERF) if os detection not performed
   	* 1 (OS_PERF) if os detection performed
   	* 2 (OS_PERF_UNREL) if an unreliable os detection has been performed */
  	int osscan_flag;
};

#endif
