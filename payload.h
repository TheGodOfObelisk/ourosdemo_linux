#ifndef MY_PAYLOAD_H
#define MY_PAYLOAD_H
#include <stdint.h>
#include "base.h"
//It goes without saying that we need the file named "nmap-payloads"
#define PAYLOAD_FILENAME "nmap-payloads"

int init_payloads(void);
const char *get_udp_payload(u16 dport, size_t *length);
const char *udp_port2payload(u16 dport, size_t *length);

#endif