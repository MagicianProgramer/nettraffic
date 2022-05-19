//This is the code for getting network devices and openning.
//You can generate and send packet by using these funtions

#pragma once

//#include <Windows.h>

#include "pcap.h"
#include "raw.h"
#include "adapter.h"

#pragma comment(lib,"ws2_32.lib") //For winsock
#pragma comment(lib,"wpcap.lib") //For winpcap

//////////////////////////////////////
extern pcap_if_t g_devices[100];
extern pcap_if_t *g_palldevs;
extern pcap_if_t *g_pd;
extern int g_nAdapterCount;
extern pcap_t *fp;

void GetNetAdaptersAndInit();//get network adapters and initialize device by using pcap 
void CloseFunction();//free and close device

int SelectAdapter(int count);//get selected device


unsigned short in_checksum(unsigned short *ptr, int nbytes);//get check sum of packet you generate

/*void ConvertA2W(char * pszIn, LPWSTR lpwszOut);//fuction to convert unicode string into multibyte string
void ConvertW2A(LPCTSTR lpszIn, char * pszOut);//fuction to convert multibyte string into unicode string*/

////////////////////////////////
////////////////////////////////
////////////////////////////////
//these functions are for generating packet and sending it by  using pcap
void sendtcppacket(const char* srcip, int nsrcport, const char *destip, int destport, char* dump, int len);
void sendudppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
void sendicmppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
void sendhttppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
void sendsmtppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
void sendpop3packet(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
void sendftppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
