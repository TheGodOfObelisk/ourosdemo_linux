#ifndef MY_TARGET_GROUP_H
#define MY_TARGET_GROUP_H

#include <list>
#include <stdlib.h>

class NetBlock;

class TargetGroup {
public:
  NetBlock *netblock;

  TargetGroup() {
    this->netblock = NULL;
  }

  ~TargetGroup();

  /* Initializes (or reinitializes) the object with a new expression,
     such as 192.168.0.0/16 , 10.1.0-5.1-254 , or
     fe80::202:e3ff:fe14:1102 .  The af parameter is AF_INET or
     AF_INET6 Returns 0 for success */
  int parse_expr(const char *target_expr, int af);
  /* Grab the next host from this expression (if any).  Returns 0 and
     fills in ss if successful.  ss must point to a pre-allocated
     sockaddr_storage structure */
  int get_next_host(struct sockaddr_storage *ss, size_t *sslen);
  /* Returns true iff the given address is the one that was resolved to create
     this target group; i.e., not one of the addresses derived from it with a
     netmask. */
  bool is_resolved_address(const struct sockaddr_storage *ss) const;
  /* Return a string of the name or address that was resolved for this group. */
  const char *get_resolved_name(void) const;
  /* Return the list of addresses that the name for this group resolved to, but
     which were not scanned, if it came from a name resolution. */
  const std::list<struct sockaddr_storage> &get_unscanned_addrs(void) const;
  /* is the current expression a named host */
  int get_namedhost() const;
};

#endif