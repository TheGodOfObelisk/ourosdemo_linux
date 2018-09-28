#ifndef PORTREASONS_H
#define PORTREASONS_H

#include "base.h"

#include <netinet/in.h>
#include <map>

/* passed to the print_state_summary.
 * STATE_REASON_EMPTY will append to the current line, prefixed with " because of"
 * STATE_REASON_FULL will start a new line, prefixed with "Reason:" */
#define STATE_REASON_EMPTY 0
#define STATE_REASON_FULL 1


/* Passed to reason_str to determine if string should be in
 * plural of singular form */
#define SINGULAR 1
#define PLURAL 2

class Target;
class PortList;

typedef unsigned short reason_t;

enum reason_codes {
        ER_RESETPEER, ER_CONREFUSED, ER_CONACCEPT,
        ER_SYNACK, ER_SYN, ER_UDPRESPONSE, ER_PROTORESPONSE, ER_ACCES,

        ER_NETUNREACH, ER_HOSTUNREACH, ER_PROTOUNREACH,
        ER_PORTUNREACH, ER_ECHOREPLY,

        ER_DESTUNREACH, ER_SOURCEQUENCH, ER_NETPROHIBITED,
        ER_HOSTPROHIBITED, ER_ADMINPROHIBITED,
        ER_TIMEEXCEEDED, ER_TIMESTAMPREPLY,

        ER_ADDRESSMASKREPLY, ER_NOIPIDCHANGE, ER_IPIDCHANGE,
        ER_ARPRESPONSE, ER_NDRESPONSE, ER_TCPRESPONSE, ER_NORESPONSE,
        ER_INITACK, ER_ABORT,
        ER_LOCALHOST, ER_SCRIPT, ER_UNKNOWN, ER_USER,
        ER_NOROUTE, ER_BEYONDSCOPE, ER_REJECTROUTE, ER_PARAMPROBLEM,
};

/* stored inside a Port Object and describes
 * why a port is in a specific state */
typedef struct port_reason {
        reason_t reason_id;
        union {
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
                struct sockaddr sockaddr;
        } ip_addr;
        unsigned short ttl;

        int set_ip_addr(const struct sockaddr_storage *ss);
} state_reason_t;

/* Holds various string outputs of a reason  *
 * Stored inside a map which maps enum_codes *
 * to reason_strings                                 */
class reason_string {
public:
    //Required for map
    reason_string();
    reason_string(const char * singular, const char * plural);
    const char * singular;
    const char * plural;
};

/* A map of reason_codes to plural and singular *
 * versions of the error string                 */
class reason_map_type{
private:
    std::map<reason_codes,reason_string > reason_map;
public:
    reason_map_type();
    std::map<reason_codes,reason_string>::iterator find(const reason_codes& x){
        std::map<reason_codes,reason_string>::iterator itr = reason_map.find(x);
        if(itr == reason_map.end())
            return reason_map.find(ER_UNKNOWN);
        return itr;
    };
};

/* used to calculate state reason summaries.
 * I.E 10 ports filter because of 10 no-responses */
typedef struct port_reason_summary {
        reason_t reason_id;
        unsigned int count;
        struct port_reason_summary *next;
} state_reason_summary_t;


void state_reason_init(state_reason_t *reason);

/* Function to translate ICMP code and typ to reason code */
reason_codes icmp_to_reason(u8 proto, int icmp_type, int icmp_code);

char *target_reason_str(Target *t);

/* converts a reason_id to a string. number represents the
 * amount ports in a given state. If there is more then one
 * port the plural is used, otherwise the singular is used. */
const char *reason_str(reason_t reason_id, unsigned int number);

void print_xml_state_summary(PortList *Ports, int state);

/* Build an output string based on reason and source ip address.
 * Uses static return value so previous values will be over
 * written by subsequent calls */
char *port_reason_str(state_reason_t r);

#endif