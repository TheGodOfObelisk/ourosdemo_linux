#ifndef MY_TIMING_H
#define MY_TIMING_H

#include "base.h"


struct timeout_info {
  int srtt; /* Smoothed rtt estimate (microseconds) */
  int rttvar; /* Rout trip time variance */
  int timeout; /* Current timeout threshold (microseconds) */
};

/* These are mainly initializers for ultra_timing_vals. */
struct scan_performance_vars {
  int low_cwnd;  /* The lowest cwnd (congestion window) allowed */
  int host_initial_cwnd; /* Initial congestion window for ind. hosts */
  int group_initial_cwnd; /* Initial congestion window for all hosts as a group */
  int max_cwnd; /* I should never have more than this many probes
                   outstanding */
  int slow_incr; /* How many probes are incremented for each response
                    in slow start mode */
  int ca_incr; /* How many probes are incremented per (roughly) rtt in
                  congestion avoidance mode */
  int cc_scale_max; /* The maximum scaling factor for congestion window
                       increments. */
  int initial_ssthresh;
  double group_drop_cwnd_divisor; /* all-host group cwnd divided by this
                                     value if any packet drop occurs */
  double group_drop_ssthresh_divisor; /* used to drop the group ssthresh when
                                         any drop occurs */
  double host_drop_ssthresh_divisor; /* used to drop the host ssthresh when
                                         any drop occurs */

  /* Do initialization after the global NmapOps table has been filled in. */
  void init();
};

#endif