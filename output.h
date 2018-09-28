#ifndef MY_OUTPUT_H
#define MY_OUTPUT_H

#include "target.h"

#include <time.h>
#include <string>
#define LOG_NUM_FILES 4 /* # of values that actual files (they must come first */
#define LOG_NORMAL 1
#define LOG_STDERR 2048
#define PCAP_OPEN_ERRMSG "Call to pcap_open_live() failed three times. "\
"There are several possible reasons for this, depending on your operating "\
"system:\nLINUX: If you are getting Socket type not supported, try "\
"modprobe af_packet or recompile your kernel with PACKET enabled.\n "\
 "*BSD:  If you are getting device not configured, you need to recompile "\
 "your kernel with Berkeley Packet Filter support.  If you are getting "\
 "No such file or directory, try creating the device (eg cd /dev; "\
 "MAKEDEV <device>; or use mknod).\n*WINDOWS:  Nmap only supports "\
 "ethernet interfaces on Windows for most operations because Microsoft "\
 "disabled raw sockets as of Windows XP SP2.  Depending on the reason for "\
 "this error, it is possible that the --unprivileged command-line argument "\
 "will help.\nSOLARIS:  If you are trying to scan localhost or the "\
 "address of an interface and are getting '/dev/lo0: No such file or "\
 "directory' or 'lo0: No DLPI device found', complain to Sun.  I don't "\
 "think Solaris can support advanced localhost scans.  You can probably "\
 "use \"-Pn -sT localhost\" though.\n\n"

struct PortInfo{
	u16 portno;
	std::string state;
	std::string protocol;
	std::string serviceinfo;
};

struct target_in_file{//收集目标主机的信息，收集好之后利用它来写文件
	int	target_id;//unique id to identify
	unsigned long starttime;//对该主机扫描的开始时间
	unsigned long endtime;//对该主机扫描的结束时间
	std::string target_ip;// new? malloc不知道该给string分配多少空间
	int address_family;//AF_INET ipv4或ipv6
	std::string os_name;//操作系统名称
	std::string device_type;//设备类型
	std::string mac; //mac地址（直接连接，无直接连接，网关的mac地址）
	std::list<struct PortInfo> PortInfoList;
};

void print_xml_finished_open(time_t timep, const struct timeval *tv);

void print_xml_hosts();

/* Writes a heading for a full scan report ("Nmap scan report for..."),
   including host status and DNS records. */
void write_host_header(Target *currenths);

/* Prints the MAC address if one was found for the target (generally
   this means that the target is directly connected on an ethernet
   network.  This only prints to human output -- XML is handled by a
   separate call ( print_MAC_XML_Info ) because it needs to be printed
   in a certain place to conform to DTD. */
void printmacinfo(Target *currenths);

/* Print "times for host" output with latency. */
void printtimes(Target *currenths);

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to
   machine log. */
void write_host_status(Target *currenths);

/* Prints the familiar Nmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Grepable
   output and the XML output.  It is pretty ugly -- in particular I
   should write helper functions to handle the table creation */
void printportoutput(Target *currenths, PortList *plist,target_in_file *t);

/* Displays reason summary messages */
void print_state_summary(PortList *Ports, unsigned short type);

/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(Target *currenths,target_in_file *t);


#endif