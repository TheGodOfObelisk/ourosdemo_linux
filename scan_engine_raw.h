#ifndef MY_SCAN_ENGINE_RAW_H
#define MY_SCAN_ENGINE_RAW_H

#include "base.h"
#include <vector>
class HostScanStats;
class UltraProbe;
class UltraScanInfo;
class Target;
int get_ping_pcap_result(UltraScanInfo *USI, struct timeval *stime);
void increment_base_port();
void begin_sniffer(UltraScanInfo *USI, std::vector<Target *> &Targets);

UltraProbe *sendIPScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                            const probespec *pspec, u8 tryno, u8 pingseq);
UltraProbe *sendArpScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                             u8 tryno, u8 pingseq);
// UltraProbe *sendNDScanProbe(UltraScanInfo *USI, HostScanStats *hss,
//                             u8 tryno, u8 pingseq);

bool get_arp_result(UltraScanInfo *USI, struct timeval *stime);
bool get_pcap_result(UltraScanInfo *USI, struct timeval *stime);
#endif