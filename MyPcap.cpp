
#include "stdafx.h"
#include "MyPcap.h"


CMyPcap::CMyPcap()
{
	m_nAdapterCount = 0;
}


CMyPcap::~CMyPcap()
{
}

void ConvertW2A(LPCTSTR lpszIn, char * pszOut)
{
	if (lpszIn == NULL || pszOut == NULL) return;

	int nLen = ::WideCharToMultiByte(CP_ACP, 0, lpszIn, -1, NULL, 0, NULL, NULL);
	::ZeroMemory(pszOut, nLen + 1);
	::WideCharToMultiByte(CP_ACP, 0, lpszIn, -1, pszOut, nLen, NULL, NULL);
}

void ConvertA2W(char * pszIn, LPWSTR lpwszOut)
{
	if (pszIn == NULL || lpwszOut == NULL) return;

	int nLen = ::MultiByteToWideChar(CP_ACP, 0, pszIn, -1, NULL, 0);
	::ZeroMemory((PBYTE)lpwszOut, 2 * (nLen + 1));
	::MultiByteToWideChar(CP_ACP, 0, pszIn, -1, lpwszOut, nLen);
}


unsigned short CMyPcap::in_CheckSum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (SHORT)~sum;

	return(answer);
}


void CMyPcap::GetNetAdaptersAndInit()
{
	pcap_t *fp;
	pcap_addr_t *a;


	char sgatewayip[16], errbuf[PCAP_ERRBUF_SIZE + 1], *data;
	int gatewayip, process_id = GetCurrentProcessId();

	char acUserName[100];
	DWORD nUserName = sizeof(acUserName);
	GetUserNameA(acUserName, &nUserName);

	loadiphlpapi();

	// Retrieve the interfaces list from winpcap
	pcap_findalldevs(&m_palldevs, errbuf);


	//printf("The following devices found : \n\n");
	for (m_pdev = m_palldevs; m_pdev; m_pdev = m_pdev->next)	//Print the devices
	{
		m_devices[m_nAdapterCount] = *m_pdev;
		m_nAdapterCount++;
	}
}

void CMyPcap::CloseMyPcap()
{
	pcap_freealldevs(m_palldevs);
	pcap_close(m_fp);
}


int CMyPcap::SelectAdapter(int count)
{
	//////////////////////
	pcap_addr_t *a;
	in_addr srcip, destip;

	char sgatewayip[16], errbuf[PCAP_ERRBUF_SIZE + 1], *data;
	int gatewayip, process_id = GetCurrentProcessId();

	char acUserName[100];
	DWORD nUserName = sizeof(acUserName);

	a = m_devices[count].addresses;

	//Get mac addresses of source and gateway ips
	srcip = ((struct sockaddr_in *)a->addr)->sin_addr;
	GetMacAddress(m_src_mac, srcip);

	GetGateway(srcip, sgatewayip, &gatewayip);
	destip.s_addr = gatewayip;

	GetMacAddress(m_dst_mac, destip);

	//Now open the selected device
	if ((m_fp = pcap_open_live(m_devices[count].name,        // name of the device
		100,						// portion of the packet to capture (only the first 100 bytes)
		1,  // promiscuous mode
		1000,						// read timeout
									// authentication on the remote machine
		errbuf						// error buffer
	)) == NULL)
	{
		return -1;
	}

	return 0;
}

void CMyPcap::sendtcppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len)
{
	u_char packet[65536];

	ETHER_HDR *ehdr;
	IPV4_HDR *iphdr;
	TCP_HDR *tcphdr;
	P_HDR pseudo_header;
	//char *dump = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* data;

	// *******************  Ethernet Header *****************

	ehdr = (PETHER_HDR)packet;

	memcpy(ehdr->source, m_src_mac, 6);	//Source Mac address
	memcpy(ehdr->dest, m_dst_mac, 6);	//Destination MAC address
	ehdr->type = htons(0x0800); //IP Frames

								// *******************  IP Header *****************

	iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));

	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
	iphdr->ip_id = htons(2);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 3;
	iphdr->ip_protocol = IPPROTO_TCP;
	iphdr->ip_srcaddr = inet_addr(srcip);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_CheckSum((unsigned short*)iphdr, sizeof(IPV4_HDR));


	// *******************  TCP Header *****************
	tcphdr = (PTCP_HDR)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));

	tcphdr->source_port = htons(srcport);//src port
	tcphdr->dest_port = htons(destport);//dest port
	tcphdr->sequence = 0;
	tcphdr->acknowledge = 0;
	tcphdr->reserved_part1 = 0;
	tcphdr->data_offset = 5;
	tcphdr->fin = 0;
	tcphdr->syn = 1;
	tcphdr->rst = 0;
	tcphdr->psh = 0;
	tcphdr->ack = 0;
	tcphdr->urg = 0;
	tcphdr->ecn = 0;
	tcphdr->cwr = 0;
	tcphdr->window = htons(64240);
	tcphdr->checksum = 0;
	tcphdr->urgent_pointer = 0;

	// *******************  Data Dump *****************
	data = (char*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR));
	memcpy(data, dump, len);

	// *******************  Checksum calculation *****************
	pseudo_header.source_address = inet_addr(srcip); //forge it >:) srcip.s_addr; 
	pseudo_header.dest_address = inet_addr(destip);
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(sizeof(TCP_HDR) + len);
	memcpy(&pseudo_header.tcp, tcphdr, sizeof TCP_HDR);


	unsigned char seudo[65355];
	memcpy(seudo, &pseudo_header, sizeof(P_HDR));
	memcpy(seudo + sizeof(P_HDR), data, len);

	tcphdr->checksum = in_CheckSum((unsigned short*)seudo, sizeof(P_HDR) + len);

	//Uncomment this line if you want to flood

	int res = pcap_sendpacket(m_fp, packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
}

void CMyPcap::sendudppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len)
{
	u_char packet[65536];

	ETHER_HDR *ehdr;
	IPV4_HDR *iphdr;
	UDP_HDR *udphdr;
	char* data;

	// *******************  Ethernet Header *****************

	ehdr = (PETHER_HDR)packet;

	char destmac[] = { 0xff,0xff,0xff,0xff,0xff,0xff };
	memcpy(ehdr->source, m_src_mac, 6);	//Source Mac address
	memcpy(ehdr->dest, destmac, 6);	//Destination MAC address
	ehdr->type = htons(0x0800); //IP Frames

								// *******************  IP Header *****************

	iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));

	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(UDP_HDR) + len);
	iphdr->ip_id = htons(2);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 3;
	iphdr->ip_protocol = IPPROTO_UDP;
	iphdr->ip_srcaddr = inet_addr(srcip);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_CheckSum((unsigned short*)iphdr, sizeof(IPV4_HDR));


	// *******************  UDP Header *****************
	udphdr = (PUDP_HDR)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));

	udphdr->source_port = htons(srcport);//src port
	udphdr->dest_port = htons(destport);//dest port
	udphdr->udp_length = htons(sizeof(UDP_HDR) + len);
	udphdr->udp_checksum = 0;

	// *******************  Data Dump *****************
	data = (char*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(UDP_HDR));
	memcpy(data, dump, len);

	// *******************  Checksum calculation *****************
	unsigned char seudo[65355];
	memcpy(seudo, &ehdr, sizeof(ETHER_HDR));
	memcpy(seudo + sizeof(ETHER_HDR), &iphdr, sizeof(IPV4_HDR));
	memcpy(seudo + sizeof(ETHER_HDR) + sizeof(IPV4_HDR), &udphdr, sizeof(UDP_HDR));
	memcpy(seudo + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(UDP_HDR), data, len);

	udphdr->udp_checksum = in_CheckSum((unsigned short*)seudo, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(UDP_HDR) + len);


	//Uncomment this line if you want to flood

	int res = pcap_sendpacket(m_fp, packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(UDP_HDR) + len);
}

void CMyPcap::sendicmppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len)
{
	u_char packet[65536];

	ETHER_HDR *ehdr;
	IPV4_HDR *iphdr;
	ICMP_HDR *icmphdr;
	char* data;

	// *******************  Ethernet Header *****************

	ehdr = (PETHER_HDR)packet;

	memcpy(ehdr->source, m_src_mac, 6);	//Source Mac address
	memcpy(ehdr->dest, m_dst_mac, 6);	//Destination MAC address
	ehdr->type = htons(0x0800); //IP Frames

								// *******************  IP Header *****************

	iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));

	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(ICMP_HDR) + len);
	iphdr->ip_id = htons(2);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 3;
	iphdr->ip_protocol = IPPROTO_ICMP;
	iphdr->ip_srcaddr = inet_addr(srcip);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_CheckSum((unsigned short*)iphdr, sizeof(IPV4_HDR));


	// *******************  ICMP Header *****************
	icmphdr = (ICMP_HDR*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));

	icmphdr->type = 0x08;//src port
	icmphdr->code = 0x00;//dest port
	icmphdr->checksum = 0;
	icmphdr->miscel = 0x00010001;

	// *******************  Data Dump *****************
	data = (char*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(ICMP_HDR));
	memcpy(data, dump, len);

	// *******************  Checksum calculation *****************
	unsigned char seudo[65355];
	memcpy(seudo, &ehdr, sizeof(ETHER_HDR));
	memcpy(seudo + sizeof(ETHER_HDR), &iphdr, sizeof(IPV4_HDR));
	memcpy(seudo + sizeof(ETHER_HDR) + sizeof(IPV4_HDR), &icmphdr, sizeof(ICMP_HDR));
	memcpy(seudo + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(ICMP_HDR), data, len);

	icmphdr->checksum = in_CheckSum((unsigned short*)seudo, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(ICMP_HDR) + len);


	//Uncomment this line if you want to flood

	int res = pcap_sendpacket(m_fp, packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(ICMP_HDR) + len);
}

void CMyPcap::sendhttppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len)
{
	char httpbuf[1000] = { 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a };
	char tmp[1000];
	sprintf_s(tmp, "Host:%s:%d\r\n\r\n", destip, destport);
	memcpy(httpbuf + 16, tmp, strlen(tmp));
	memcpy(httpbuf + 16 + strlen(tmp), dump, len);
	len = 16 + strlen(tmp) + len;


	///////////////
	u_char packet[65536];

	ETHER_HDR *ehdr;
	IPV4_HDR *iphdr;
	TCP_HDR *tcphdr;
	P_HDR pseudo_header;
	//char *dump = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* data;

	// *******************  Ethernet Header *****************

	ehdr = (PETHER_HDR)packet;

	memcpy(ehdr->source, m_src_mac, 6);	//Source Mac address
	memcpy(ehdr->dest, m_dst_mac, 6);	//Destination MAC address
	ehdr->type = htons(0x0800); //IP Frames

								// *******************  IP Header *****************

	iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));

	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
	iphdr->ip_id = htons(2);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 3;
	iphdr->ip_protocol = IPPROTO_TCP;
	iphdr->ip_srcaddr = inet_addr(srcip);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_CheckSum((unsigned short*)iphdr, sizeof(IPV4_HDR));


	// *******************  TCP Header *****************
	tcphdr = (PTCP_HDR)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));

	tcphdr->source_port = htons(srcport);//src port
	tcphdr->dest_port = htons(destport);//dest port
	tcphdr->sequence = 0;
	tcphdr->acknowledge = 0;
	tcphdr->reserved_part1 = 0;
	tcphdr->data_offset = 5;
	tcphdr->fin = 0;
	tcphdr->syn = 0;
	tcphdr->rst = 0;
	tcphdr->psh = 1;
	tcphdr->ack = 1;
	tcphdr->urg = 0;
	tcphdr->ecn = 0;
	tcphdr->cwr = 0;
	tcphdr->window = htons(64240);
	tcphdr->checksum = 0;
	tcphdr->urgent_pointer = 0;

	// *******************  Data Dump *****************
	data = (char*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR));
	memcpy(data, dump, len);

	///////////////////////////////////////////

	// *******************  Checksum calculation *****************
	pseudo_header.source_address = inet_addr(srcip); //forge it >:) srcip.s_addr; 
	pseudo_header.dest_address = inet_addr(destip);
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(sizeof(TCP_HDR) + len);
	memcpy(&pseudo_header.tcp, tcphdr, sizeof TCP_HDR);
	memcpy(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR), httpbuf, len);


	unsigned char seudo[65355];
	memcpy(seudo, &pseudo_header, sizeof(P_HDR));
	memcpy(seudo + sizeof(P_HDR), httpbuf, len);

	//tcphdr->checksum = in_checksum((unsigned short*)seudo, sizeof(P_HDR) + len);

	//Uncomment this line if you want to flood

	int res = pcap_sendpacket(m_fp, packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
}

void CMyPcap::sendsmtppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len)
{
	char smtpbuf[1000];
	char tmp[1000];
	sprintf_s(tmp, " 250 Sender Ok\r\n");
	memcpy(smtpbuf, tmp, strlen(tmp));
	memcpy(smtpbuf + strlen(tmp), dump, len);
	len = strlen(tmp) + len;


	///////////////
	u_char packet[65536];

	ETHER_HDR *ehdr;
	IPV4_HDR *iphdr;
	TCP_HDR *tcphdr;
	P_HDR pseudo_header;
	//char *dump = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* data;

	// *******************  Ethernet Header *****************

	ehdr = (PETHER_HDR)packet;

	memcpy(ehdr->source, m_src_mac, 6);	//Source Mac address
	memcpy(ehdr->dest, m_dst_mac, 6);	//Destination MAC address
	ehdr->type = htons(0x0800); //IP Frames

								// *******************  IP Header *****************

	iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));

	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
	iphdr->ip_id = htons(2);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 3;
	iphdr->ip_protocol = IPPROTO_TCP;
	iphdr->ip_srcaddr = inet_addr(srcip);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_CheckSum((unsigned short*)iphdr, sizeof(IPV4_HDR));


	// *******************  TCP Header *****************
	tcphdr = (PTCP_HDR)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));

	tcphdr->source_port = htons(srcport);//src port
	tcphdr->dest_port = htons(destport);//dest port
	tcphdr->sequence = 0;
	tcphdr->acknowledge = 0;
	tcphdr->reserved_part1 = 0;
	tcphdr->data_offset = 5;
	tcphdr->fin = 0;
	tcphdr->syn = 0;
	tcphdr->rst = 0;
	tcphdr->psh = 1;
	tcphdr->ack = 1;
	tcphdr->urg = 0;
	tcphdr->ecn = 0;
	tcphdr->cwr = 0;
	tcphdr->window = htons(64240);
	tcphdr->checksum = 0;
	tcphdr->urgent_pointer = 0;

	// *******************  Data Dump *****************
	data = (char*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR));
	memcpy(data, dump, len);

	///////////////////////////////////////////

	// *******************  Checksum calculation *****************
	pseudo_header.source_address = inet_addr(srcip); //forge it >:) srcip.s_addr; 
	pseudo_header.dest_address = inet_addr(destip);
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(sizeof(TCP_HDR) + len);
	memcpy(&pseudo_header.tcp, tcphdr, sizeof TCP_HDR);
	memcpy(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR), smtpbuf, len);


	unsigned char seudo[65355];
	memcpy(seudo, &pseudo_header, sizeof(P_HDR));
	memcpy(seudo + sizeof(P_HDR), smtpbuf, len);

	//tcphdr->checksum = in_checksum((unsigned short*)seudo, sizeof(P_HDR) + len);

	//Uncomment this line if you want to flood

	int res = pcap_sendpacket(m_fp, packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
}

void CMyPcap::sendpop3packet(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len)
{
	char popbuf[1000];
	char tmp[1000];
	sprintf_s(tmp, "+OK Mailbox scan listing follows\r\n");
	memcpy(popbuf, tmp, strlen(tmp));
	memcpy(popbuf + strlen(tmp), dump, len);
	len = strlen(tmp) + len;


	///////////////
	u_char packet[65536];

	ETHER_HDR *ehdr;
	IPV4_HDR *iphdr;
	TCP_HDR *tcphdr;
	P_HDR pseudo_header;
	//char *dump = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* data;

	// *******************  Ethernet Header *****************

	ehdr = (PETHER_HDR)packet;

	memcpy(ehdr->source, m_src_mac, 6);	//Source Mac address
	memcpy(ehdr->dest, m_dst_mac, 6);	//Destination MAC address
	ehdr->type = htons(0x0800); //IP Frames

								// *******************  IP Header *****************

	iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));

	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
	iphdr->ip_id = htons(2);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 3;
	iphdr->ip_protocol = IPPROTO_TCP;
	iphdr->ip_srcaddr = inet_addr(srcip);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_CheckSum((unsigned short*)iphdr, sizeof(IPV4_HDR));


	// *******************  TCP Header *****************
	tcphdr = (PTCP_HDR)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));

	tcphdr->source_port = htons(srcport);//src port
	tcphdr->dest_port = htons(destport);//dest port
	tcphdr->sequence = 0;
	tcphdr->acknowledge = 0;
	tcphdr->reserved_part1 = 0;
	tcphdr->data_offset = 5;
	tcphdr->fin = 0;
	tcphdr->syn = 0;
	tcphdr->rst = 0;
	tcphdr->psh = 1;
	tcphdr->ack = 1;
	tcphdr->urg = 0;
	tcphdr->ecn = 0;
	tcphdr->cwr = 0;
	tcphdr->window = htons(64240);
	tcphdr->checksum = 0;
	tcphdr->urgent_pointer = 0;

	// *******************  Data Dump *****************
	data = (char*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR));
	memcpy(data, dump, len);

	///////////////////////////////////////////

	// *******************  Checksum calculation *****************
	pseudo_header.source_address = inet_addr(srcip); //forge it >:) srcip.s_addr; 
	pseudo_header.dest_address = inet_addr(destip);
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(sizeof(TCP_HDR) + len);
	memcpy(&pseudo_header.tcp, tcphdr, sizeof TCP_HDR);
	memcpy(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR), popbuf, len);


	unsigned char seudo[65355];
	memcpy(seudo, &pseudo_header, sizeof(P_HDR));
	memcpy(seudo + sizeof(P_HDR), popbuf, len);

	//tcphdr->checksum = in_checksum((unsigned short*)seudo, sizeof(P_HDR) + len);

	//Uncomment this line if you want to flood

	int res = pcap_sendpacket(m_fp, packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
}

void CMyPcap::sendftppacket(const char* srcip, int srcport, const char *destip, int destport, char* dump, int len)
{
	char ftpbuf[1000];
	char tmp[1000];
	sprintf_s(tmp, "220-\r\n");
	memcpy(ftpbuf, tmp, strlen(tmp));
	memcpy(ftpbuf + strlen(tmp), dump, len);
	len = strlen(tmp) + len;


	///////////////
	u_char packet[65536];

	ETHER_HDR *ehdr;
	IPV4_HDR *iphdr;
	TCP_HDR *tcphdr;
	P_HDR pseudo_header;
	//char *dump = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* data;

	// *******************  Ethernet Header *****************

	ehdr = (PETHER_HDR)packet;

	memcpy(ehdr->source, m_src_mac, 6);	//Source Mac address
	memcpy(ehdr->dest, m_dst_mac, 6);	//Destination MAC address
	ehdr->type = htons(0x0800); //IP Frames

								// *******************  IP Header *****************

	iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));

	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
	iphdr->ip_id = htons(2);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 3;
	iphdr->ip_protocol = IPPROTO_TCP;
	iphdr->ip_srcaddr = inet_addr(srcip);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_CheckSum((unsigned short*)iphdr, sizeof(IPV4_HDR));


	// *******************  TCP Header *****************
	tcphdr = (PTCP_HDR)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));

	tcphdr->source_port = htons(srcport);//src port
	tcphdr->dest_port = htons(destport);//dest port
	tcphdr->sequence = 0;
	tcphdr->acknowledge = 0;
	tcphdr->reserved_part1 = 0;
	tcphdr->data_offset = 5;
	tcphdr->fin = 0;
	tcphdr->syn = 0;
	tcphdr->rst = 0;
	tcphdr->psh = 1;
	tcphdr->ack = 1;
	tcphdr->urg = 0;
	tcphdr->ecn = 0;
	tcphdr->cwr = 0;
	tcphdr->window = htons(64240);
	tcphdr->checksum = 0;
	tcphdr->urgent_pointer = 0;

	// *******************  Data Dump *****************
	data = (char*)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR));
	memcpy(data, dump, len);

	///////////////////////////////////////////

	// *******************  Checksum calculation *****************
	pseudo_header.source_address = inet_addr(srcip); //forge it >:) srcip.s_addr; 
	pseudo_header.dest_address = inet_addr(destip);
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(sizeof(TCP_HDR) + len);
	memcpy(&pseudo_header.tcp, tcphdr, sizeof TCP_HDR);
	memcpy(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR), ftpbuf, len);


	unsigned char seudo[65355];
	memcpy(seudo, &pseudo_header, sizeof(P_HDR));
	memcpy(seudo + sizeof(P_HDR), ftpbuf, len);

	//tcphdr->checksum = in_checksum((unsigned short*)seudo, sizeof(P_HDR) + len);

	//Uncomment this line if you want to flood

	int res = pcap_sendpacket(m_fp, packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR) + len);
}
