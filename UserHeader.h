#pragma once
// Define the various device type values.
#define FILE_DEVICE_DRVFIREWALL  0x00654322

// Macro definition for defining IOCTL and FSCTL function control codes. 
#define DRVFIREWALL_IOCTL_INDEX  0x830

// The MONO device driver IOCTLs
#define START_IP_HOOK CTL_CODE(FILE_DEVICE_DRVFIREWALL, DRVFIREWALL_IOCTL_INDEX, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define STOP_IP_HOOK CTL_CODE(FILE_DEVICE_DRVFIREWALL, DRVFIREWALL_IOCTL_INDEX+1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ADD_FILTER CTL_CODE(FILE_DEVICE_DRVFIREWALL, DRVFIREWALL_IOCTL_INDEX+2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define CLEAR_FILTER CTL_CODE(FILE_DEVICE_DRVFIREWALL, DRVFIREWALL_IOCTL_INDEX+3, METHOD_BUFFERED, FILE_ANY_ACCESS)

//struct to define filter rules
typedef struct filter
{
	USHORT protocol;		//protocol used

	ULONG sourceIp;			//source ip address
	ULONG destinationIp;	//destination ip address

	USHORT sourcePort;		//source port
	USHORT destinationPort; //destination port

	BOOLEAN drop;			//if true, the packet will be drop, otherwise the packet pass
}IPFilter;
