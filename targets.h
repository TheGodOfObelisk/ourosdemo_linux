//To manage info of hosts
#ifndef MY_TARGETS_H
#define MY_TARGETS_H

#include "target.h"
#include "targetgroup.h"
#include <list>

class HostGroupState {
public:
  /* The maximum number of entries we want to allow storing in defer_buffer. */
  static const unsigned int DEFER_LIMIT = 64;

  HostGroupState(int lookahead, int randomize, int argc, const char *argv[]);
  ~HostGroupState();
  Target **hostbatch;

  /* The defer_buffer is a place to store targets that have previously been
     returned but that can't be used right now. They wait in defer_buffer until
     HostGroupState::undefer is called, at which point they all move to the end
     of the undeferred list. HostGroupState::next_target always pulls from the
     undeferred list before returning anything new. */
  std::list<Target *> defer_buffer;
  std::list<Target *> undeferred;

  int argc;
  const char **argv;
  int max_batch_sz; /* The size of the hostbatch[] array */
  int current_batch_sz; /* The number of VALID members of hostbatch[] */
  int next_batch_no; /* The index of the next hostbatch[] member to be given
                        back to the user */
  int randomize; /* Whether each batch should be "shuffled" prior to the ping
                    scan (they will also be out of order when given back one
                    at a time to the client program */
  TargetGroup current_group; /* For batch chunking -- targets in queue */

  /* Returns true iff the defer buffer is not yet full. */
  bool defer(Target *t);
  void undefer();
  const char *next_expression();
  Target *next_target();//wtf, where is your definition?
};

/* Ports is the list of ports the user asked to be scanned (0 terminated),
   you can just pass NULL (it is only a stupid optimization that needs it) */
Target *nexthost(HostGroupState *hs,const addrset *exclude_group,
                 struct scan_lists *ports, int pingtype);

bool target_needs_new_hostgroup(Target **targets, int targets_sz, const Target *target);

/* Returns the last host obtained by nexthost.  It will be given again the next
   time you call nexthost(). */
void returnhost(HostGroupState *hs);

#endif