//it combines osscan.h and osscan2.h in source code
#ifndef OSSCAN_H
#define OSSCAN_H

#include "base.h"
#include "eth.h"
#include "timing.h"
// #include "FingerPrintResults.h"
// #include "target.h"
#include <time.h>
#include <string.h>
#include <vector>
#include <list>
#include <pcap.h>
/******************************************************************************
 * CONSTANT DEFINITIONS                                                       *
 ******************************************************************************/
class FingerPrintResultsIPv4;
class Target;

//I do not know where it is
#define OP_SUCCESS 1
#define OP_FAILURE 0

#define NUM_FPTESTS    13

/* The number of tries we normally do.  This may be increased if
   the target looks like a good candidate for fingerprint submission, or fewer
   if the user gave the --max-os-tries option */
#define STANDARD_OS2_TRIES 2

// The minimum (and target) amount of time to wait between probes
// sent to a single host, in milliseconds.
#define OS_PROBE_DELAY 25

// The target amount of time to wait between sequencing probes sent to
// a single host, in milliseconds.  The ideal is 500ms because of the
// common 2Hz timestamp frequencies.  Less than 500ms and we might not
// see any change in the TS counter (and it gets less accurate even if
// we do).  More than 500MS and we risk having two changes (and it
// gets less accurate even if we have just one).  So we delay 100MS
// between probes, leaving 500MS between 1st and 6th.
#define OS_SEQ_PROBE_DELAY 100

/* How many syn packets do we send to TCP sequence a host? */
#define NUM_SEQ_SAMPLES 6

/* TCP Timestamp Sequence */
#define TS_SEQ_UNKNOWN 0
#define TS_SEQ_ZERO 1 /* At least one of the timestamps we received back was 0 */
#define TS_SEQ_2HZ 2
#define TS_SEQ_100HZ 3
#define TS_SEQ_1000HZ 4
#define TS_SEQ_OTHER_NUM 5
#define TS_SEQ_UNSUPPORTED 6 /* System didn't send back a timestamp */

#define IPID_SEQ_UNKNOWN 0
#define IPID_SEQ_INCR 1  /* simple increment by one each time */
#define IPID_SEQ_BROKEN_INCR 2 /* Stupid MS -- forgot htons() so it
                                  counts by 256 on little-endian platforms */
#define IPID_SEQ_RPI 3 /* Goes up each time but by a "random" positive
                          increment */
#define IPID_SEQ_RD 4 /* Appears to select IPID using a "random" distributions (meaning it can go up or down) */
#define IPID_SEQ_CONSTANT 5 /* Contains 1 or more sequential duplicates */
#define IPID_SEQ_ZERO 6 /* Every packet that comes back has an IP.ID of 0 (eg Linux 2.4 does this) */
#define IPID_SEQ_INCR_BY_2 7 /* simple increment by two each time */

#define OSSCAN_SUCCESS 0
#define OSSCAN_NOMATCHES -1
#define OSSCAN_TOOMANYMATCHES -2

/* We won't even consider matches with a lower accuracy than this */
#define OSSCAN_GUESS_THRESHOLD 0.85

/******************************************************************************
 * TYPE AND STRUCTURE DEFINITIONS                                             *
 ******************************************************************************/
/* The method used to calculate the Target::distance, included in OS
   fingerprints. */
enum dist_calc_method {
        DIST_METHOD_NONE,
        DIST_METHOD_LOCALHOST,
        DIST_METHOD_DIRECT,
        DIST_METHOD_ICMP,
        DIST_METHOD_TRACEROUTE
};





/* Different kinds of Ipids. */
struct ipid_info {
  u32 tcp_ipids[NUM_SEQ_SAMPLES];
  u32 tcp_closed_ipids[NUM_SEQ_SAMPLES];
  u32 icmp_ipids[NUM_SEQ_SAMPLES];
};

struct seq_info {
  int responses;
  int ts_seqclass; /* TS_SEQ_* defines in nmap.h */
  int ipid_seqclass; /* IPID_SEQ_* defines in nmap.h */
  u32 seqs[NUM_SEQ_SAMPLES];
  u32 timestamps[NUM_SEQ_SAMPLES];
  int index;
  u16 ipids[NUM_SEQ_SAMPLES];
  time_t lastboot; /* 0 means unknown */
};

typedef enum OFProbeType {
  OFP_UNSET,
  OFP_TSEQ,
  OFP_TOPS,
  OFP_TECN,
  OFP_T1_7,
  OFP_TICMP,
  OFP_TUDP
} OFProbeType;

struct AVal {
  const char *attribute;
  const char *value;

  bool operator<(const AVal& other) const {
    return strcmp(attribute, other.attribute) < 0;
  }
};

struct udpprobeinfo {
  u16 iptl;
  u16 ipid;
  u16 ipck;
  u16 sport;
  u16 dport;
  u16 udpck;
  u16 udplen;
  u8 patternbyte;
  struct in_addr target;
};

struct OS_Classification {
  const char *OS_Vendor;
  const char *OS_Family;
  const char *OS_Generation; /* Can be NULL if unclassified */
  const char *Device_Type;
  std::vector<const char *> cpe;
};

/* A description of an operating system: a human-readable name and a list of
   classifications. */
struct FingerMatch {
  int line; /* For reference prints, the line # in nmap-os-db */
  /* For IPv6 matches, the number of fingerprints that contributed to this
   * classification group */
  unsigned short numprints;
  char *OS_name;
  std::vector<OS_Classification> OS_class;

  FingerMatch() {
    line = -1;
    OS_name = NULL;
  }
};


struct FingerTest {
  const char *name;
  std::vector<struct AVal> results;
  bool operator<(const FingerTest& other) const {
    return strcmp(name, other.name) < 0;
  }
};


struct FingerPrint {
  FingerMatch match;
  std::vector<FingerTest> tests;
  FingerPrint();
  void sort();
};
/* This structure contains the important data from the fingerprint
   database (nmap-os-db) */
struct FingerPrintDB {
  FingerPrint *MatchPoints;
  std::vector<FingerPrint *> prints;

  FingerPrintDB();
  ~FingerPrintDB();
};

/* The OS database consists of many small strings, many of which appear
   thousands of times. It pays to allocate memory only once for each unique
   string, and have all references point at the one allocated value. */
const char *string_pool_insert(const char *s);
const char *string_pool_sprintf(const char *fmt, ...);

const char *mergeFPs(FingerPrint *FPs[], int numFPs, bool isGoodFP,
                           const struct sockaddr_storage *addr, int distance,
                           enum dist_calc_method distance_calculation_method,
                           const u8 *mac, int openTcpPort, int closedTcpPort,
                           int closedUdpPort, bool wrapit);

/******************************************************************************
 * CLASS DEFINITIONS                                                          *
 ******************************************************************************/
class OFProbe;
class HostOsScanStats;
class HostOsScan;
class HostOsScanInfo;
class OsScanInfo;


/** Represents an OS detection probe. It does not contain the actual packet
 * that is sent to the target but contains enough information to generate
 * it (such as the probe type and its subid). It also stores timing
 * information. */
class OFProbe {

 public:
  OFProbe();

  /* The literal string for the current probe type. */
  const char *typestr();

  /* Type of the probe: for what os fingerprinting test? */
  OFProbeType type;

  /* Subid of this probe to separate different tcp/udp/icmp. */
  int subid;

  /* Try (retransmission) number of this probe */
  int tryno;

  /* A packet may be timedout for a while before being retransmitted
     due to packet sending rate limitations */
  bool retransmitted;

  struct timeval sent;

  /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
  struct timeval prevSent;
};


/* Stores the status for a host being scanned in a scan round. */
class HostOsScanStats {

 friend class HostOsScan;

 public:
  HostOsScanStats(Target *t);
  ~HostOsScanStats();
  void initScanStats();
  struct eth_nfo *fill_eth_nfo(struct eth_nfo *eth, eth_t *ethsd) const;
  void addNewProbe(OFProbeType type, int subid);
  void removeActiveProbe(std::list<OFProbe *>::iterator probeI);
  /* Get an active probe from active probe list identified by probe type
   * and subid.  returns probesActive.end() if there isn't one. */
  std::list<OFProbe *>::iterator getActiveProbe(OFProbeType type, int subid);
  void moveProbeToActiveList(std::list<OFProbe *>::iterator probeI);
  void moveProbeToUnSendList(std::list<OFProbe *>::iterator probeI);
  unsigned int numProbesToSend() {return probesToSend.size();}
  unsigned int numProbesActive() {return probesActive.size();}
  FingerPrint *getFP() {return FP;}

  Target *target; /* the Target */
  struct seq_info si;
  struct ipid_info ipid;

  /* distance, distance_guess: hop count between us and the target.
   *
   * Possible values of distance:
   *   0: when scan self;
   *   1: when scan a target on the same network segment;
   * >=1: not self, not same network and nmap has got the icmp reply to the U1 probe.
   *  -1: none of the above situations.
   *
   * Possible values of distance_guess:
   *  -1: nmap fails to get a valid ttl by all kinds of probes.
   * >=1: a guessing value based on ttl. */
  int distance;
  int distance_guess;

  /* Returns the amount of time taken between sending 1st tseq probe
   * and the last one.  Zero is
   * returned if we didn't send the tseq probes because there was no
   * open tcp port */
  double timingRatio();
  double cc_scale();

 private:
  /* Ports of the targets used in os fingerprinting. */
  int openTCPPort, closedTCPPort, closedUDPPort;

  /* Probe list used in tests. At first, probes are linked in
   * probesToSend; when a probe is sent, it will be removed from
   * probesToSend and appended to probesActive. If any probes in
   * probesActive are timedout, they will be moved to probesToSend and
   * sent again till expired. */
  std::list<OFProbe *> probesToSend;
  std::list<OFProbe *> probesActive;

  /* A record of total number of probes that have been sent to this
   * host, including retransmitted ones. */
  unsigned int num_probes_sent;
  /* Delay between two probes.    */
  unsigned int sendDelayMs;
  /* When the last probe is sent. */
  struct timeval lastProbeSent;

  struct ultra_timing_vals timing;

  /* Fingerprint of this target. When a scan is completed, it'll
   * finally be passed to hs->target->FPR->FPs[x]. */
  FingerPrint *FP;
  FingerTest *FPtests[NUM_FPTESTS];
  #define FP_TSeq  FPtests[0]
  #define FP_TOps  FPtests[1]
  #define FP_TWin  FPtests[2]
  #define FP_TEcn  FPtests[3]
  #define FP_T1_7_OFF 4
  #define FP_T1    FPtests[4]
  #define FP_T2    FPtests[5]
  #define FP_T3    FPtests[6]
  #define FP_T4    FPtests[7]
  #define FP_T5    FPtests[8]
  #define FP_T6    FPtests[9]
  #define FP_T7    FPtests[10]
  #define FP_TUdp  FPtests[11]
  #define FP_TIcmp FPtests[12]
  struct AVal *TOps_AVs[6]; /* 6 AVs of TOps */
  struct AVal *TWin_AVs[6]; /* 6 AVs of TWin */

  /* The following are variables to store temporary results
   * during the os fingerprinting process of this host. */
  u16 lastipid;
  struct timeval seq_send_times[NUM_SEQ_SAMPLES];

  int TWinReplyNum; /* how many TWin replies are received. */
  int TOpsReplyNum; /* how many TOps replies are received. Actually it is the same with TOpsReplyNum. */

  struct ip *icmpEchoReply; /* To store one of the two icmp replies */
  int storedIcmpReply; /* Which one of the two icmp replies is stored? */

  struct udpprobeinfo upi; /* info of the udp probe we sent */
};

/* These are statistics for the whole group of Targets */
class ScanStats {

 public:
  ScanStats();
  bool sendOK(); /* Returns true if the system says that sending is OK. */
  double cc_scale();

  struct ultra_timing_vals timing;
  struct timeout_info to;      /* rtt/timeout info                */
  int num_probes_active;       /* Total number of active probes   */
  int num_probes_sent;         /* Number of probes sent in total. */
  int num_probes_sent_at_last_wait;
};


/* This class does the scan job, setting and using the status of a host in
 * the host's HostOsScanStats. */
class HostOsScan {

 public:
  HostOsScan(Target *t); /* OsScan need a target to set eth stuffs */
  ~HostOsScan();

  pcap_t *pd;
  ScanStats *stats;

  /* (Re)Initialize the parameters that will be used during the scan.*/
  void reInitScanSystem();

  void buildSeqProbeList(HostOsScanStats *hss);
  void updateActiveSeqProbes(HostOsScanStats *hss);

  void buildTUIProbeList(HostOsScanStats *hss);
  void updateActiveTUIProbes(HostOsScanStats *hss);

  /* send the next probe in the probe list of the hss */
  void sendNextProbe(HostOsScanStats *hss);

  /* Process one response. If the response is useful, return true. */
  bool processResp(HostOsScanStats *hss, struct ip *ip, unsigned int len, struct timeval *rcvdtime);

  /* Make up the fingerprint. */
  void makeFP(HostOsScanStats *hss);

  /* Check whether the host is sendok. If not, fill _when_ with the
   * time when it will be sendOK and return false; else, fill it with
   * now and return true. */
  bool hostSendOK(HostOsScanStats *hss, struct timeval *when);

  /* Check whether it is ok to send the next seq probe to the host. If
   * not, fill _when_ with the time when it will be sendOK and return
   * false; else, fill it with now and return true. */
  bool hostSeqSendOK(HostOsScanStats *hss, struct timeval *when);


  /* How long I am currently willing to wait for a probe response
   * before considering it timed out.  Uses the host values from
   * target if they are available, otherwise from gstats.  Results
   * returned in MICROseconds.  */
  unsigned long timeProbeTimeout(HostOsScanStats *hss);

  /* If there are pending probe timeouts, fills in when with the time
   * of the earliest one and returns true.  Otherwise returns false
   * and puts now in when. */
  bool nextTimeout(HostOsScanStats *hss, struct timeval *when);

  /* Adjust various timing variables based on pcket receipt. */
  void adjust_times(HostOsScanStats *hss, OFProbe *probe, struct timeval *rcvdtime);

private:
  /* Probe send functions. */
  void sendTSeqProbe(HostOsScanStats *hss, int probeNo);
  void sendTOpsProbe(HostOsScanStats *hss, int probeNo);
  void sendTEcnProbe(HostOsScanStats *hss);
  void sendT1_7Probe(HostOsScanStats *hss, int probeNo);
  void sendTUdpProbe(HostOsScanStats *hss, int probeNo);
  void sendTIcmpProbe(HostOsScanStats *hss, int probeNo);
  /* Response process functions. */
  bool processTSeqResp(HostOsScanStats *hss, struct ip *ip, int replyNo);
  bool processTOpsResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo);
  bool processTWinResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo);
  bool processTEcnResp(HostOsScanStats *hss, struct ip *ip);
  bool processT1_7Resp(HostOsScanStats *hss, struct ip *ip, int replyNo);
  bool processTUdpResp(HostOsScanStats *hss, struct ip *ip);
  bool processTIcmpResp(HostOsScanStats *hss, struct ip *ip, int replyNo);

  /* Generic sending functions used by the above probe functions. */
  int send_tcp_probe(HostOsScanStats *hss,
                     int ttl, bool df, u8* ipopt, int ipoptlen,
                     u16 sport, u16 dport, u32 seq, u32 ack,
                     u8 reserved, u8 flags, u16 window, u16 urp,
                     u8 *options, int optlen,
                     char *data, u16 datalen);
  int send_icmp_echo_probe(HostOsScanStats *hss,
                           u8 tos, bool df, u8 pcode,
                           unsigned short id, u16 seq, u16 datalen);
  int send_closedudp_probe(HostOsScanStats *hss,
                           int ttl, u16 sport, u16 dport);

  void makeTSeqFP(HostOsScanStats *hss);
  void makeTOpsFP(HostOsScanStats *hss);
  void makeTWinFP(HostOsScanStats *hss);

  bool get_tcpopt_string(struct tcp_hdr *tcp, int mss, char *result, int maxlen);

  int rawsd;    /* Raw socket descriptor */
  eth_t *ethsd; /* Ethernet handle       */

  unsigned int tcpSeqBase;    /* Seq value used in TCP probes                 */
  unsigned int  tcpAck;       /* Ack value used in TCP probes                 */
  int tcpMss;                 /* TCP MSS value used in TCP probes             */
  int udpttl;                 /* TTL value used in the UDP probe              */
  unsigned short icmpEchoId;  /* ICMP Echo Identifier value for ICMP probes   */
  unsigned short icmpEchoSeq; /* ICMP Echo Sequence value used in ICMP probes */

  /* Source port number in TCP probes. Different probes will use an arbitrary
   * offset value of it. */
  int tcpPortBase;
  int udpPortBase;
};


/* Maintains a link of incomplete HostOsScanInfo. */
class OsScanInfo {

 public:
  OsScanInfo(std::vector<Target *> &Targets);
  ~OsScanInfo();
  float starttime;

  /* If you remove from this, you had better adjust nextI too (or call
   * resetHostIterator() afterward). Don't let this list get empty,
   * then add to it again, or you may mess up nextI (I'm not sure) */
  std::list<HostOsScanInfo *> incompleteHosts;

  unsigned int numIncompleteHosts() {return incompleteHosts.size();}
  HostOsScanInfo *findIncompleteHost(struct sockaddr_storage *ss);

  /* A circular buffer of the incompleteHosts.  nextIncompleteHost() gives
     the next one.  The first time it is called, it will give the
     first host in the list.  If incompleteHosts is empty, returns
     NULL. */
  HostOsScanInfo *nextIncompleteHost();

  /* Resets the host iterator used with nextIncompleteHost() to the
     beginning.  If you remove a host from incompleteHosts, call this
     right afterward */
  void resetHostIterator() { nextI = incompleteHosts.begin(); }

  int removeCompletedHosts();

 private:
  unsigned int numInitialTargets;
  std::list<HostOsScanInfo *>::iterator nextI;
};

/* The overall os scan information of a host:
 *  - Fingerprints gotten from every scan round;
 *  - Maching results of these fingerprints.
 *  - Is it timeout/completed?
 *  - ... */
class HostOsScanInfo {

 public:
  HostOsScanInfo(Target *t, OsScanInfo *OSI);
  ~HostOsScanInfo();

  Target *target;       /* The target                                  */
  FingerPrintResultsIPv4 *FPR;
  OsScanInfo *OSI;      /* The OSI which contains this HostOsScanInfo  */
  FingerPrint **FPs;    /* Fingerprints of the host                    */
  FingerPrintResultsIPv4 *FP_matches; /* Fingerprint-matching results      */
  bool timedOut;        /* Did it time out?                            */
  bool isCompleted;     /* Has the OS detection been completed?        */
  HostOsScanStats *hss; /* Scan status of the host in one scan round   */
};

/** This is the class that performs OS detection (both IPv4 and IPv6).
  * Using it is simple, just call os_scan() passing a list of targets.
  * The results of the detection will be stored inside the supplied
  * target objects. */
class OSScan {

 private:
  int chunk_and_do_scan(std::vector<Target *> &Targets, int family);
  int os_scan_ipv4(std::vector<Target *> &Targets);
  int os_scan_ipv6(std::vector<Target *> &Targets);

  public:
   OSScan();
   ~OSScan();
   void reset();
   int os_scan(std::vector<Target *> &Targets);
};

/* Takes a fingerprint and looks for matches inside the passed in
   reference fingerprint DB.  The results are stored in in FPR (which
   must point to an instantiated FingerPrintResultsIPv4 class) -- results
   will be reverse-sorted by accuracy.  No results below
   accuracy_threshold will be included.  The max matches returned is
   the maximum that fits in a FingerPrintResultsIPv4 class.  */
void match_fingerprint(const FingerPrint *FP, FingerPrintResultsIPv4 *FPR,
                       const FingerPrintDB *DB, double accuracy_threshold);

/* Compares 2 fingerprints -- a referenceFP (can have expression
   attributes) with an observed fingerprint (no expressions).  If
   verbose is nonzero, differences will be printed.  The comparison
   accuracy (between 0 and 1) is returned).  If MatchPoints is not NULL, it is
   a special "fingerprints" which tells how many points each test is worth. */
double compare_fingerprints(const FingerPrint *referenceFP, const FingerPrint *observedFP,
                            const FingerPrint *MatchPoints, int verbose);

int get_initial_ttl_guess(u8 ttl);

int get_ipid_sequence_16(int numSamples, u32 *ipids, int islocalhost);

int get_diffs(u32 *ipid_diffs, int numSamples, u32 *ipids, int islocalhost);

int identify_sequence(int numSamples, u32 *ipid_diffs, int islocalhost);
//it seems that the fourth parameter is forgotten: , int allipideqz

/* These functions take a file/db name and open+parse it, returning an
   (allocated) FingerPrintDB containing the results.  They exit with
   an error message in the case of error. */
FingerPrintDB *parse_fingerprint_file(const char *fname);

FingerPrintDB *parse_fingerprint_reference_file(const char *dbname);

/* Convert a TCP sequence prediction difficulty index like 1264386
   into a difficulty string like "Worthy Challenge */
const char *seqidx2difficultystr(unsigned long idx);

const char *ipidclass2ascii(int seqclass);

const char *tsseqclass2ascii(int seqclass);

#endif