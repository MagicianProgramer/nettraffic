
//This is the code for getting network devices and openning.
//You can generate and send packet by using these funtions

#pragma once

#include "pcap.h"
#include "raw.h"
#include "adapter.h"

#pragma comment(lib,"ws2_32.lib") //For winsock
#pragma comment(lib,"wpcap.lib") //For winpcap

#define PORT_HTTP	80
#define PORT_SMTP	25
#define PORT_POP3	110
#define PORT_ENIP	2222
#define PORT_FTP	21
#define PORT_RPC	111
#define PORT_NTP	123

class CMyPcap
{
public:
	CMyPcap();
	~CMyPcap();

public:
	pcap_if_t m_devices[100];
	pcap_if_t *m_palldevs;
	pcap_if_t *m_pdev;
	int m_nAdapterCount;
	pcap_t *m_fp;
	u_char m_src_mac[6];
	u_char m_dst_mac[6];

public:
	void GetNetAdaptersAndInit();//get network adapters and initialize device by using pcap 
	void CloseMyPcap();//free and close device
	int SelectAdapter(int count);//get selected device

	unsigned short in_CheckSum(unsigned short *ptr, int nbytes);//get check sum of packet you generate

	////////////////////////////////
	////////////////////////////////
	////////////////////////////////
	//these functions are for generating packet and sending it by  using pcap
	void sendtcppacket(const char* srcip, int nsrcport, const char *destip, int destport, char* dump, int len);
	void sendhttppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
	void sendsmtppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
	void sendpop3packet(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
	void sendftppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
	
	void sendudppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);

	void sendicmppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len);
};

void ConvertA2W(char * pszIn, LPWSTR lpwszOut);//fuction to convert unicode string into multibyte string
void ConvertW2A(LPCTSTR lpszIn, char * pszOut);//fuction to convert multibyte string into unicode string