#ifndef FINGERPRINTRESULTS_H
#define FINGERPRINTRESULTS_H
class FingerPrintResults;
class Target;
#include "osscan.h"

/* Maximum number of results allowed in one of these things ... */
#define MAX_FP_RESULTS 36

struct OS_Classification_Results {
  struct OS_Classification *OSC[MAX_FP_RESULTS];
  double OSC_Accuracy[MAX_FP_RESULTS];
  int OSC_num_perfect_matches; // Number of perfect matches in OSC[\]
  int OSC_num_matches; // Number of matches total in OSC[] (and, of course, _accuracy[])
  int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, OSSCAN_SUCCESS, etc */
};


class FingerPrintResults{
public:
	FingerPrintResults();
	virtual~FingerPrintResults();//in fact, it is a virtual function
	//we need to correct it later

   double accuracy[MAX_FP_RESULTS]; /* Percentage of match (1.0 == perfect
                                      match) in same order as matches[] below */
   FingerMatch *matches[MAX_FP_RESULTS]; /* ptrs to matching references --
                                              highest accuracy matches first */
   int num_perfect_matches; /* Number of 1.0 accuracy matches in matches[] */
   int num_matches; /* Total number of matches in matches[] */
   int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES,
                          OSSCAN_SUCCESS, etc */

	/* Ensures that the results are available and then returns them.
   You should only call this AFTER all matching has been completed
   (because results are cached and won't change if new matches[] are
   added.)  All OS Classes in the results will be unique, and if there
   are any perfect (accuracy 1.0) matches, only those will be
   returned */
  const struct OS_Classification_Results *getOSClassification();

   int osscan_opentcpport; /* Open TCP port used for scanning (if one found --
                          otherwise -1) */
   int osscan_closedtcpport; /* Closed TCP port used for scanning (if one found --
                            otherwise -1) */
   int osscan_closedudpport;  /* Closed UDP port used for scanning (if one found --
                            otherwise -1) */
   int distance; /* How "far" is this FP gotten from? */
   int distance_guess; /* How "far" is this FP gotten from? by guessing based on ttl. */
   enum dist_calc_method distance_calculation_method;

   /* The largest ratio we have seen of time taken vs. target time
     between sending 1st tseq probe and sending first ICMP echo probe.
     Zero means we didn't see any ratios (the tseq probes weren't
     sent), 1 is ideal, and larger values are undesirable from a
     consistency standpoint. */
  double maxTimingRatio;

  bool incomplete; /* Were we unable to send all necessary probes? */
  /* If the fingerprint is of potentially poor quality, we don't want to
   print it and ask the user to submit it.  In that case, the reason
   for skipping the FP is returned as a static string.  If the FP is
   great and should be printed, NULL is returned. */
  virtual const char *OmitSubmissionFP();

  virtual const char *merge_fpr(const Target *currenths, bool isGoodFP, bool wrapit) const = 0;
private:
  bool isClassified; // Whether populateClassification() has been called
  /* Goes through fingerprinting results to populate OSR */	
  void populateClassification();
  bool classAlreadyExistsInResults(struct OS_Classification *OSC);
  struct OS_Classification_Results OSR;
};//remian to fill

class FingerPrintResultsIPv4 : public FingerPrintResults {
public:
  FingerPrint **FPs; /* Fingerprint data obtained from host */
  int numFPs;

  FingerPrintResultsIPv4();
  virtual ~FingerPrintResultsIPv4();
  const char *merge_fpr(const Target *currenths, bool isGoodFP, bool wrapit) const;
};
 //class FingerPrintResultsIPv6 ........

#endif