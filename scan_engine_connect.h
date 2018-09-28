#ifndef MY_SCAN_ENGINE_CONNECT_H
#define MY_SCAN_ENGINE_CONNECT_H

#include "base.h"

class UltraProbe;
class UltraScanInfo;
class HostScanStats;

UltraProbe *sendConnectScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                                 u16 destport, u8 tryno, u8 pingseq);
bool do_one_select_round(UltraScanInfo *USI, struct timeval *stime);

#endif