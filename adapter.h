/*
  Author : Silver Moon (m00n.silv3r@gmail.com)
  Description : A mini replacemnt for iphlpapi.h to be used with VC++ 6.0
  This file can be used on systems where iphlapi.h is not available
*/
#pragma once

#include "windows.h"
#include "time.h"
#include <IPTypes.h>

#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH 8

//Necessary Structs
/*typedef struct 
{
	char String[4 * 4];
} IP_ADDRESS_STRING_, *PIP_ADDRESS_STRING_, IP_MASK_STRING_, *PIP_MASK_STRING_;

typedef struct _IP_ADDR_STRING 
{
	struct _IP_ADDR_STRING* Next;
	IP_ADDRESS_STRING_ IpAddress;
	IP_MASK_STRING_ IpMask;
	DWORD Context;
} IP_ADDR_STRING_ , *PIP_ADDR_STRING_;

typedef struct _IP_ADAPTER_INFO 
{ 
    struct _IP_ADAPTER_INFO* Next; 
    DWORD           ComboIndex; 
    char            AdapterName[MAX_ADAPTER_NAME_LENGTH + 4]; 
    char            Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4]; 
    UINT            AddressLength; 
    BYTE            Address[MAX_ADAPTER_ADDRESS_LENGTH]; 
    DWORD           Index; 
    UINT            Type; 
    UINT            DhcpEnabled; 
    PIP_ADDR_STRING_ CurrentIpAddress; 
    IP_ADDR_STRING_  IpAddressList; 
    IP_ADDR_STRING_  GatewayList; 
    IP_ADDR_STRING_  DhcpServer; 
    BOOL            HaveWins; 
    IP_ADDR_STRING_  PrimaryWinsServer; 
    IP_ADDR_STRING_  SecondaryWinsServer; 
    time_t          LeaseObtained; 
    time_t          LeaseExpires; 
} IP_ADAPTER_INFO_, *PIP_ADAPTER_INFO_;*/


//Functions
void loadiphlpapi();
void GetGateway(struct in_addr ip , char *sgatewayip , int *gatewayip);
void GetMacAddress(unsigned char *mac , in_addr destip);

//Loads from Iphlpapi.dll
typedef DWORD (WINAPI* psendarp)(in_addr DestIP, in_addr SrcIP, PULONG pMacAddr, PULONG PhyAddrLen );
typedef DWORD (WINAPI* pgetadaptersinfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen );

extern psendarp SendArp;
extern pgetadaptersinfo GetAdaptersInfo_;