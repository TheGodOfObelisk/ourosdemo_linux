#include "FingerPrintResults.h"
#include "scanops.h"
extern ScanOps o;

FingerPrintResults::FingerPrintResults(){
  num_perfect_matches = num_matches = 0;
  overall_results = OSSCAN_NOMATCHES;
  memset(accuracy, 0, sizeof(accuracy));
  isClassified = false;
  osscan_opentcpport = osscan_closedtcpport = osscan_closedudpport = -1;
  distance = -1;
  distance_guess = -1;
  distance_calculation_method = DIST_METHOD_NONE;
  maxTimingRatio = 0;
  incomplete = false;
}

FingerPrintResults::~FingerPrintResults(){

}

FingerPrintResultsIPv4::FingerPrintResultsIPv4() {
  FPs = (FingerPrint **) safe_zalloc(o.maxOSTries() * sizeof(FingerPrint *));
  numFPs = 0;
}

FingerPrintResultsIPv4::~FingerPrintResultsIPv4() {
  int i;

  /* Free OS fingerprints of OS scanning was done */
  for(i=0; i < numFPs; i++) {
    delete(FPs[i]);
    FPs[i] = NULL;
  }
  numFPs = 0;
  free(FPs);
}

/* If the fingerprint is of potentially poor quality, we don't want to
   print it and ask the user to submit it.  In that case, the reason
   for skipping the FP is returned as a static string.  If the FP is
   great and should be printed, NULL is returned. */
const char *FingerPrintResults::OmitSubmissionFP() {
  static char reason[128];

  if (o.scan_delay > 500) { // This can screw up the sequence timing
    Snprintf(reason, sizeof(reason), "Scan delay (%d) is greater than 500", o.scan_delay);
    return reason;
  }

  if (o.timing_level > 4)
    return "Timing level 5 (Insane) used";

  if (osscan_opentcpport <= 0)
    return "Missing an open TCP port so results incomplete";

  if (osscan_closedtcpport <= 0)
    return "Missing a closed TCP port so results incomplete";

  /* This can happen if the TTL in the response to the UDP probe is somehow
     greater than the TTL in the probe itself. We exclude -1 because that is
     used to mean the distance is unknown, though there's a chance it could
     have come from the distance calculation. */
  if (distance < -1) {
    Snprintf(reason, sizeof(reason), "Host distance (%d network hops) appears to be negative", distance);
    return reason;
  }

  if (distance > 5) {
    Snprintf(reason, sizeof(reason), "Host distance (%d network hops) is greater than five", distance);
    return reason;
  }

  if (maxTimingRatio > 1.4) {
    Snprintf(reason, sizeof(reason), "maxTimingRatio (%e) is greater than 1.4", maxTimingRatio);
    return reason;
  }

  if (osscan_closedudpport < 0 && !o.udpscan) {
    /* If we didn't get a U1 response, that might be just
       because we didn't search for an closed port rather than
       because this OS doesn't respond to that sort of probe.
       So we don't print FP if U1 response is lacking AND no UDP
       scan was performed. */
    return "Didn't receive UDP response. Please try again with -sSU";
  }

  if (incomplete) {
    return "Some probes failed to send so results incomplete";
  }

  return NULL;
}

const struct OS_Classification_Results *FingerPrintResults::getOSClassification() {
  if (!isClassified) { populateClassification(); isClassified = true; }
  return &OSR;
}

/* Goes through fingerprinting results to populate OSR */
void FingerPrintResults::populateClassification() {
  std::vector<OS_Classification>::iterator osclass;
  int printno;

  OSR.OSC_num_perfect_matches = OSR.OSC_num_matches = 0;
  OSR.overall_results = OSSCAN_SUCCESS;

  if (overall_results == OSSCAN_TOOMANYMATCHES) {
    // The normal classification overflowed so we don't even have all the perfect matches,
    // I don't see any good reason to do classification.
    OSR.overall_results = OSSCAN_TOOMANYMATCHES;
    return;
  }

  for(printno = 0; printno < num_matches; printno++) {
    // a single print may have multiple classifications
    for (osclass = matches[printno]->OS_class.begin();
         osclass != matches[printno]->OS_class.end();
         osclass++) {
      if (!classAlreadyExistsInResults(&*osclass)) {
        // Then we have to add it ... first ensure we have room
        if (OSR.OSC_num_matches == MAX_FP_RESULTS) {
          // Out of space ... if the accuracy of this one is 100%, we have a problem
          if (printno < num_perfect_matches)
            OSR.overall_results = OSSCAN_TOOMANYMATCHES;
          return;
        }

        // We have space, but do we even want this one?  No point
        // including lesser matches if we have 1 or more perfect
        // matches.
        if (OSR.OSC_num_perfect_matches > 0 && printno >= num_perfect_matches) {
          return;
        }

        // OK, we will add the new class
        OSR.OSC[OSR.OSC_num_matches] = &*osclass;
        OSR.OSC_Accuracy[OSR.OSC_num_matches] = accuracy[printno];
        if (printno < num_perfect_matches)
          OSR.OSC_num_perfect_matches++;
        OSR.OSC_num_matches++;
      }
    }
  }

  if (OSR.OSC_num_matches == 0)
    OSR.overall_results = OSSCAN_NOMATCHES;

  return;
}

/* Return true iff s and t are both NULL or both the same string. */
static bool strnulleq(const char *s, const char *t) {
  if (s == NULL && t == NULL)
    return true;
  else if (s == NULL || t == NULL)
    return false;
  else
    return strcmp(s, t) == 0;
}

// Go through any previously entered classes to see if this is a dupe;
bool FingerPrintResults::classAlreadyExistsInResults(struct OS_Classification *OSC) {
  int i;

  for (i=0; i < OSR.OSC_num_matches; i++) {
    if (strnulleq(OSC->OS_Vendor, OSR.OSC[i]->OS_Vendor) &&
        strnulleq(OSC->OS_Family, OSR.OSC[i]->OS_Family) &&
        strnulleq(OSC->Device_Type, OSR.OSC[i]->Device_Type) &&
        strnulleq(OSC->OS_Generation, OSR.OSC[i]->OS_Generation)) {
    // Found a duplicate!
    return true;
    }
  }

  // Went through all the results -- no duplicates found
  return false;
}