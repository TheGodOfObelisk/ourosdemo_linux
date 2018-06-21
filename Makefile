edit:main.o base.o target.o scanops.o netutil.o \
			errorhandle.o timing.o osscan.o \
			FingerPrintResults.o portlist.o \
			scan_engine.o portreasons.o
	g++ -o edit main.o base.o target.o scanops.o \
			netutil.o errorhandle.o timing.o osscan.o \
			FingerPrintResults.o portlist.o \
			scan_engine.o portreasons.o -lpcap -lpthread
main.o:main.cpp
#	g++ -c main.cpp -lpcap -lpthread
base.o:base.cpp
#	g++ -c base.cpp
target.o:target.cpp
#	g++ -c target.cpp
scanops.o:scanops.cpp
#	g++ -c scanops.cpp
netutil.o:netutil.cpp
#	g++ -c netutil.cpp
errorhandle.o:errorhandle.cpp
#	g++ -c errorhandle.cpp
timing.o:timing.cpp
#	g++ -c timing.cpp
osscan.o:osscan.cpp
FingerPrintResults.o:FingerPrintResults.cpp
portlist.o:portlist.cpp
scan_engine.o:scan_engine.cpp
portreasons.o:portreasons.cpp
clean:
	rm edit main.o base.o target.o scanops.o netutil.o \
		errorhandle.o timing.o osscan.o \
		FingerPrintResults.o portlist.o \
		scan_engine.o portreasons.o
