edit:main.o base.o portlist.o scanops.o netutil.o \
			errorhandle.o timing.o osscan.o \
			FingerPrintResults.o target.o \
			scan_engine.o portreasons.o output.o\
			scan_lists.o intf.o addr.o eth.o ip.o route.o\
            ip6.o util.o targets.o targetgroup.o\
            xml.o tcpip.o scan_engine_raw.o\
            payload.o scan_engine_connect.o\
            arp.o MACLookup.o charpool.o \
            protocols.o services.o ScanOutputTable.o
	g++ -o edit main.o base.o portlist.o scanops.o \
			netutil.o errorhandle.o timing.o osscan.o \
			FingerPrintResults.o target.o \
			scan_engine.o portreasons.o \
			output.o scan_lists.o intf.o \
			addr.o eth.o ip.o  route.o ip6.o \
			util.o targets.o targetgroup.o \
			xml.o tcpip.o scan_engine_raw.o \
			payload.o scan_engine_connect.o \
			arp.o MACLookup.o charpool.o  \
			protocols.o services.o ScanOutputTable.o\
			libpcap.a
main.o:main.cpp
	g++  -c main.cpp libpcap.a
base.o:base.cpp
	g++  -c base.cpp libpcap.a
portlist.o:portlist.cpp
	g++  -c portlist.cpp libpcap.a
target.o:target.cpp
	g++  -c target.cpp libpcap.a
scanops.o:scanops.cpp
	g++  -c scanops.cpp libpcap.a
netutil.o:netutil.cpp
	g++  -c netutil.cpp libpcap.a
errorhandle.o:errorhandle.cpp
	g++  -c errorhandle.cpp libpcap.a
timing.o:timing.cpp
	g++  -c timing.cpp libpcap.a
osscan.o:osscan.cpp
	g++  -c osscan.cpp libpcap.a
FingerPrintResults.o:FingerPrintResults.cpp
	g++  -c FingerPrintResults.cpp libpcap.a
scan_engine.o:scan_engine.cpp
	g++  -c scan_engine.cpp libpcap.a
portreasons.o:portreasons.cpp
	g++  -c portreasons.cpp libpcap.a
output.o:output.cpp
	g++  -c output.cpp libpcap.a
scan_lists.o:scan_lists.cpp
	g++  -c scan_lists.cpp libpcap.a
intf.o:intf.cpp
	g++  -c intf.cpp libpcap.a
addr.o:addr.cpp
	g++  -c addr.cpp libpcap.a
eth.o:eth.cpp
	g++  -c eth.cpp libpcap.a
ip.o:ip.cpp
	g++  -c ip.cpp libpcap.a
route.o:route.cpp
	g++  -c route.cpp libpcap.a
ip6.o:ip6.cpp
	g++  -c ip6.cpp libpcap.a
util.o:util.cpp
	g++  -c util.cpp libpcap.a
targets.o:targets.cpp
	g++  -c targets.cpp libpcap.a
targetgroup.o:targetgroup.cpp
	g++  -c targetgroup.cpp libpcap.a
xml.o:xml.cpp
	g++  -c xml.cpp libpcap.a
tcpip.o:tcpip.cpp
	g++  -c tcpip.cpp libpcap.a
scan_engine_raw.o:scan_engine_raw.cpp
	g++  -c scan_engine_raw.cpp libpcap.a
payload.o:payload.cpp
	g++  -c payload.cpp libpcap.a
scan_engine_connect.o:scan_engine_connect.cpp
	g++  -c scan_engine_connect.cpp libpcap.a
arp.o:arp.cpp
	g++  -c arp.cpp libpcap.a
MACLookup.o:MACLookup.cpp
	g++  -c MACLookup.cpp libpcap.a
charpool.o:charpool.cpp
	g++  -c charpool.cpp libpcap.a
protocols.o:protocols.cpp
	g++  -c protocols.cpp libpcap.a
services.o:services.cpp
	g++  -c services.cpp libpcap.a
ScanOutputTable.o:ScanOutputTable.cpp
	g++  -c ScanOutputTable.cpp libpcap.a
clean:
	rm edit main.o base.o target.o scanops.o netutil.o \
		errorhandle.o timing.o osscan.o \
		FingerPrintResults.o portlist.o \
		scan_engine.o portreasons.o output.o\
		scan_lists.o intf.o addr.o eth.o\
		ip.o route.o ip6.o util.o targets.o\
		targetgroup.o xml.o tcpip.o scan_engine_raw.o\
		payload.o scan_engine_connect.o arp.o\
		MACLookup.o charpool.o protocols.o \
		services.o ScanOutputTable.o
