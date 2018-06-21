#include "base.h"
#include "timing.h"
#include "target.h"
#include "netutil.h"
#include "scanops.h"
#include "errorhandle.h"
#include <cstdlib>//? I have stdlib.h in errorhandle.h
#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <netinet/in.h>

using namespace std;

struct tm *local_time;

ScanOps o;
static vector<string> route_dst_hosts;

extern void set_program_name(const char *name);
static void our_welcome(){
	cout<<"/****************************************************/"<<endl;
	cout<<"/*                     WELCOME!                     */"<<endl;
	cout<<"/*                  Our OS Scan Demo                */"<<endl;
	cout<<"/****************************************************/"<<endl;
}

static void printusage(){
	cout<<"usage: please input least one scan target!"<<endl;
}

void parse_options(int argc, char **argv){
	//remain to fill
}

void apply_delayed_options(){
	//remain to fill
}

int main(int argc, char *argv[]){
	our_welcome();
	set_program_name(argv[0]);
	//cout<<argv[0]<<endl;
	//argv[0] indicates the name of our program
	//test of libpcap
	char errBuf[PCAP_ERRBUF_SIZE], * device;  
	
	device = pcap_lookupdev(errBuf);  
	    
	if(device){
		printf("success:device: %s\n",device);
	}
	else  
	{  
	    	printf("error: %s\n", errBuf);  
	}
	//end of libpcap test
	if(argc < 2){
		printusage();
		exit(-1);
	}
	//let's start
	if(argv[1]){
		cout<<"Scan target: "<<argv[1]<<endl;
	}
	vector<Target *> Targets;//vital
	time_t now;
	struct hostent *target = NULL;/*for hostent, all addresses are supplied in host order,
					and returned in network order*/					
	time_t timep;
	char mytime[128];
	addrset excluse_group;
	unsigned int ideal_scan_group_sz = 0;
	char myname[FQDN_LEN + 1];
	int sourceaddrwarning = 0;//Have we warned them yet about unguessable source addresses?
	unsigned int targetno;
	char hostname[FQDN_LEN + 1] = "";
	struct sockaddr_storage ss;//in netinet/in.h, this structure seems different from that in ws2def.h
	size_t sslen;
	//here we ignore something about log
	now = time(NULL);
	local_time = localtime(&now);

	Targets.reserve(100);//I don't know why
	parse_options(argc, argv);//define it later

	//tty_init();
	//put the keyboard in raw mode
	
	apply_delayed_options();

	for (unsigned int i = 0; i < route_dst_hosts.size(); i++) {
		const char *dst;
		struct sockaddr_storage ss;
	    	struct route_nfo rnfo;
	    	size_t sslen;
	    	int rc;
		
	    	dst = route_dst_hosts[i].c_str();
	    	rc = resolve(dst, 0, &ss, &sslen, o.af());
		
	    	if (rc != 0)
	      		//fatal("Can't resolve %s: %s.", dst, gai_strerror(rc));
	      		fatal("Can't resolve %s.", dst);
	    /*
	    	printf("%s\n", inet_ntop_ez(&ss, sslen));
		
	    	if (!route_dst(&ss, &rnfo, o.device, o.SourceSockAddr())) {
	      		printf("Can't route %s (%s).", dst, inet_ntop_ez(&ss, sslen));
	    	} else {
	      		printf("%s %s", rnfo.ii.devname, rnfo.ii.devfullname);
	      		printf(" srcaddr %s", inet_ntop_ez(&rnfo.srcaddr, sizeof(rnfo.srcaddr)));
	      		if (rnfo.direct_connect)
				printf(" direct");
	      		else
				printf(" nexthop %s", inet_ntop_ez(&rnfo.nexthop, sizeof(rnfo.nexthop)));
	    		}
	    	printf("\n");*/
	  }
	  route_dst_hosts.clear();

	return 0;
}
