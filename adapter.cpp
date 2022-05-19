/*
  Author : Silver Moon (m00n.silv3r@gmail.com)
  Description : A mini replacemnt for iphlpapi.h to be used with VC++ 6.0
*/

#include "adapter.h"
#include "stdio.h"

psendarp SendArp;
pgetadaptersinfo GetAdaptersInfo_;

void loadiphlpapi() 
{
	HINSTANCE hDll = LoadLibrary(L"iphlpapi.dll");
		
	GetAdaptersInfo_ = (pgetadaptersinfo)GetProcAddress(hDll,"GetAdaptersInfo");
	if(GetAdaptersInfo_==NULL)
	{
		printf("Error in iphlpapi.dll%d",GetLastError());
	}

	SendArp = (psendarp)GetProcAddress(hDll,"SendARP");
	
	if(SendArp==NULL)
	{
		printf("Error in iphlpapi.dll%d",GetLastError());
	}
}

/*
Get the gateway of a given ip
For example for ip 192.168.1.10 the gateway is 192.168.1.1
*/
void GetGateway(struct in_addr ip , char *sgatewayip , int *gatewayip) 
{
	char pAdapterInfo[5000];
	PIP_ADAPTER_INFO  AdapterInfo;
	ULONG OutBufLen = sizeof(pAdapterInfo) ;
	
	GetAdaptersInfo_((PIP_ADAPTER_INFO) pAdapterInfo, &OutBufLen); 
	for(AdapterInfo = (PIP_ADAPTER_INFO)pAdapterInfo; AdapterInfo ; AdapterInfo = AdapterInfo->Next)
	{
		if(ip.s_addr == inet_addr(AdapterInfo->IpAddressList.IpAddress.String))
		{
			strcpy_s(sgatewayip , 16, AdapterInfo->GatewayList.IpAddress.String);
		}
	}
	
	*gatewayip = inet_addr(sgatewayip);
}

/*
	Get the mac address of a given ip
*/
void GetMacAddress(unsigned char *mac , in_addr destip) 
{
	DWORD ret;
	in_addr srcip;
	ULONG MacAddr[2];
	ULONG PhyAddrLen = 6;  /* default to length of six bytes */
	
	srcip.s_addr=0;

	//Send an arp packet
	ret = SendArp(destip , srcip , MacAddr , &PhyAddrLen);
	
	//Prepare the mac address
	if(PhyAddrLen)
	{
		BYTE *bMacAddr = (BYTE *) & MacAddr;
		for (int i = 0; i < (int) PhyAddrLen; i++)
		{
			mac[i] = (char)bMacAddr[i];
		}
	}
}
