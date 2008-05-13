// ========================================================================================================================
// Droute
//
// Copyright ©2007-2008 Liam Kirton <liam@int3.ws>
// ========================================================================================================================
// Droute.cpp
//
// Created: 06/08/2007
// ========================================================================================================================

#include <winsock2.h>
#include <windows.h>

#include <iphlpapi.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <string>
#include <vector>

#include <pcap.h>

#include "Droute.h"

// ========================================================================================================================

const char *g_cDrouteVersion = "0.2.1";

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType);

DWORD WINAPI MaintenanceThreadProc(LPVOID lpParameter);
DWORD WINAPI PcapListenThreadProc(LPVOID lpParameter);

void OnListenArp(pcap_t *pAdapter, pcap_pkthdr *pPktHeader, u_char *pPktData);
void OnListenIp(pcap_t *pAdapter, pcap_pkthdr *pPktHeader, u_char *pPktData, bool bReuseData);

void GenerateInterfaceDefinitions(pcap_if_t *pDeviceList, std::vector<std::string> &interfaceStrings, std::vector<std::string> &fwdStrings);
void PrintUsage();

// ========================================================================================================================

CRITICAL_SECTION g_ConsoleCriticalSection;
HANDLE g_hExitEvent = NULL;
HANDLE g_hMaintenanceThread = NULL;

std::vector<IfStruct *> g_Interfaces;

u_int g_RouteType = 0;

// ========================================================================================================================

int main(int argc, char *argv[])
{
	std::cout << std::endl
			  << "Droute " << g_cDrouteVersion << std::endl
			  << "Copyright " << "\xB8" << "2007-2008 Liam Kirton <liam@int3.ws>" << std::endl
			  << std::endl
			  << "Built at " << __TIME__ << " on " << __DATE__ << std::endl << std::endl;

	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *pDeviceList = NULL;

	std::vector<std::string> interfaceStrings;
	std::vector<std::string> forwardStrings;

	try
	{
		for(int i = 1; i < argc; ++i)
		{
			std::string cmd = argv[i];
			std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

			if(cmd.substr(0, 5) == "/fwd:")
			{
				std::string parseForwardString = cmd.substr(5);
				
				u_int fwdBlockMarker = 0;
				while(!parseForwardString.empty() && (fwdBlockMarker != std::string::npos))
				{
					u_int nextFwdBlockMarker = parseForwardString.find(',', fwdBlockMarker + 1);
					std::string fwdBlock = parseForwardString.substr(fwdBlockMarker + ((fwdBlockMarker == 0) ? 0 : 1), nextFwdBlockMarker - fwdBlockMarker - ((fwdBlockMarker == 0) ? 0 : 1));
					fwdBlockMarker = nextFwdBlockMarker;
					forwardStrings.push_back(fwdBlock);
				}
			}
			else if(cmd == "/nat")
			{
				g_RouteType |= RouteTypeNat;
			}
			else 
			{
				interfaceStrings.push_back(cmd);
			}
		}

		if(g_RouteType != RouteTypeNat)
		{
			g_RouteType |= RouteTypeRoute;
		}
		if(interfaceStrings.size() != 2)
		{
			throw std::exception("Two Interface Definitions Required.");
		}
	}
	catch(const std::exception &e)
	{
		PrintUsage();
		std::cout << "Fatal Error: " << e.what() << std::endl;
		return -1;
	}

	InitializeCriticalSection(&g_ConsoleCriticalSection);
	SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE);

	try
	{
		if((g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		{
			throw std::exception("CreateEvent() Failed.");
		}

		if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pDeviceList, pcapErrorBuffer) == -1)
		{
			throw std::exception("pcap_findalldevs_ex() Failed.");
		}
		
		GenerateInterfaceDefinitions(pDeviceList, interfaceStrings, forwardStrings);

		if((g_hMaintenanceThread = CreateThread(NULL, 0, MaintenanceThreadProc, NULL, 0, NULL)) == NULL)
		{
			throw std::exception("CreateThread() Failed.");
		}

		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Running. Press Ctrl+C to Abort." << std::endl << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		if(e.what()[0] != '\0')
		{
			std::cout << std::endl << "Error: " << e.what() << std::endl << std::endl;
		}
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	DWORD dwThreadWaitHandlesCount = 0;
	HANDLE *hThreadWaitHandles = new HANDLE[g_Interfaces.size() + 1];
	SecureZeroMemory(hThreadWaitHandles, sizeof(HANDLE) * g_Interfaces.size());

	if(g_hMaintenanceThread != NULL)
	{
		hThreadWaitHandles[dwThreadWaitHandlesCount++] = g_hMaintenanceThread;
	}
	
	for(std::vector<IfStruct *>::iterator i = g_Interfaces.begin(); i != g_Interfaces.end(); ++i)
	{
		if((*i)->hPcapListenThread != NULL)
		{
			bool bExisting = false;
			for(DWORD j = 1; j < dwThreadWaitHandlesCount; ++j)
			{
				if(hThreadWaitHandles[j] == (*i)->hPcapListenThread)
				{
					bExisting = true;
					break;
				}
			}

			if(!bExisting)
			{
				hThreadWaitHandles[dwThreadWaitHandlesCount++] = (*i)->hPcapListenThread;
			}
		}
	}

	if(dwThreadWaitHandlesCount > 0)
	{
		if(WaitForMultipleObjects(dwThreadWaitHandlesCount,
								  hThreadWaitHandles,
								  TRUE,
								  INFINITE) != WAIT_OBJECT_0)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl << "Warning: WaitForMultipleObjects() Failed." << std::endl << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
		for(DWORD i = 0; i < dwThreadWaitHandlesCount; ++i)
		{
			CloseHandle(hThreadWaitHandles[i]);
		}
	}

	for(std::vector<IfStruct *>::iterator i = g_Interfaces.begin(); i != g_Interfaces.end(); ++i)
	{
		IfStruct *ifStruct = *i;
		if(ifStruct->hMutex != NULL)
		{
			CloseHandle(ifStruct->hMutex);
			ifStruct->hMutex = NULL;
		}

		for(std::vector<Packet>::iterator j = ifStruct->PacketQueue.begin(); j != ifStruct->PacketQueue.end(); ++j)
		{
			delete [] (*j).Data;
		}

		for(std::vector<IfStruct *>::iterator j = g_Interfaces.begin(); j != g_Interfaces.end(); ++j)
		{
			if(((*j)->pAdapter == ifStruct->pAdapter) && ((*j) != ifStruct))
			{
				ifStruct->pAdapter = NULL;
			}
		}
		if(ifStruct->pAdapter != NULL)
		{
			pcap_close(ifStruct->pAdapter);
			ifStruct->pAdapter = NULL;
		}
	}

	SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, FALSE);
	DeleteCriticalSection(&g_ConsoleCriticalSection);

	if(pDeviceList != NULL)
	{
		pcap_freealldevs(pDeviceList);
		pDeviceList = NULL;
	}

	return 0;
}

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType)
{
	if(g_hExitEvent != NULL)
	{
		SetEvent(g_hExitEvent);
	}
	return TRUE;
}

// ========================================================================================================================

DWORD WINAPI MaintenanceThreadProc(LPVOID lpParameter)
{
	try
	{
		while(WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0)
		{
			for(std::vector<IfStruct *>::iterator i = g_Interfaces.begin(); i != g_Interfaces.end(); ++i)
			{
				IfStruct *ifStruct = (*i);
				if(WaitForSingleObject(ifStruct->hMutex, 1000) != WAIT_OBJECT_0)
				{
					throw std::exception("WaitForSingleObject(ifStruct->hMutex) Failed.");
				}

				for(std::map<u_int, __int64>::iterator j = ifStruct->ArpTable.begin(); j != ifStruct->ArpTable.end(); ++j)
				{
					__int64 ifLocalTargetMac = j->second;
					u_char *pIfLocalTargetMac = reinterpret_cast<u_char *>(&ifLocalTargetMac);
					if((pIfLocalTargetMac[0] == 0xFF) &&
					   (pIfLocalTargetMac[1] == 0xFF) &&
					   (pIfLocalTargetMac[2] == 0xFF) &&
					   (pIfLocalTargetMac[3] == 0xFF) &&
					   (pIfLocalTargetMac[4] == 0xFF) &&
					   (pIfLocalTargetMac[5] == 0xFF))
					{
						if(*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6]) > 500)
						{
							continue;
						}
						else if(++(*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6])) == 500)
						{
							*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6]) = 0xFFFF;
						}
						else if((*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6]) % 100) == 0)
						{
							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << ">> ARP WHO-HAS " << ((j->first & 0x000000FF)) << "."
														   << ((j->first & 0x0000FF00) >> 8) << "."
														   << ((j->first & 0x00FF0000) >> 16) << "."
														   << ((j->first & 0xFF000000) >> 24) << " TELL "
														   << ((ifStruct->Ip & 0x000000FF)) << "."
														   << ((ifStruct->Ip & 0x0000FF00) >> 8) << "."
														   << ((ifStruct->Ip & 0x00FF0000) >> 16) << "."
														   << ((ifStruct->Ip & 0xFF000000) >> 24) << " "
														   << std::hex
														   << std::setfill('0')
														   << std::setw(2) << static_cast<u_short>(ifStruct->Mac[0]) << ":"
														   << std::setw(2) << static_cast<u_short>(ifStruct->Mac[1]) << ":"
														   << std::setw(2) << static_cast<u_short>(ifStruct->Mac[2]) << ":"
														   << std::setw(2) << static_cast<u_short>(ifStruct->Mac[3]) << ":"
														   << std::setw(2) << static_cast<u_short>(ifStruct->Mac[4]) << ":"
														   << std::setw(2) << static_cast<u_short>(ifStruct->Mac[5])
														   << std::dec << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);

							const u_int arpLookupPktMemSize = (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));
							u_char *arpLookupPktData = new u_char[arpLookupPktMemSize];

							EthernetFrameHeader *arpLookupPktEthernetFrameHeader = reinterpret_cast<EthernetFrameHeader *>(arpLookupPktData);
							SecureZeroMemory(arpLookupPktEthernetFrameHeader, sizeof(EthernetFrameHeader));
							RtlCopyMemory(&arpLookupPktEthernetFrameHeader->SourceMac, &ifStruct->Mac, 6);
							RtlFillMemory(&arpLookupPktEthernetFrameHeader->DestinationMac, 6, 0xFF);
							arpLookupPktEthernetFrameHeader->Type = EtherTypeArp;

							ArpPacketHeader *arpLookupPktArpPacketHeader = reinterpret_cast<ArpPacketHeader *>(arpLookupPktData + sizeof(EthernetFrameHeader));
							SecureZeroMemory(arpLookupPktArpPacketHeader, sizeof(ArpPacketHeader));
							arpLookupPktArpPacketHeader->HardwareAddressSpace = 0x0100;
							arpLookupPktArpPacketHeader->ProtocolAddressSpace = 0x0008;
							arpLookupPktArpPacketHeader->HardwareAddressLength = 0x06;
							arpLookupPktArpPacketHeader->ProtocolAddressLength = 0x04;
							arpLookupPktArpPacketHeader->Operation = ArpOperationWhoHas;
							RtlCopyMemory(&arpLookupPktArpPacketHeader->SenderHardwareAddress, &arpLookupPktEthernetFrameHeader->SourceMac, 6);
							RtlFillMemory(&arpLookupPktArpPacketHeader->TargetHardwareAddress, 6, 0xFF);
							arpLookupPktArpPacketHeader->SenderProtocolAddress = ifStruct->Ip;
							arpLookupPktArpPacketHeader->TargetProtocolAddress = j->first;

							pcap_sendpacket(ifStruct->pAdapter, arpLookupPktData, sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));

							delete [] arpLookupPktData;
						}
						j->second = ifLocalTargetMac;
					}
					else
					{
						if(--(*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6])) == 0xE88F)
						{
							ifLocalTargetMac = 0xFFFFFFFFFFFFFFFF;
						}
						j->second = ifLocalTargetMac;
					}
				}

				std::map<u_int, __int64>::iterator j = ifStruct->NatTable.begin();
				while(j != ifStruct->NatTable.end())
				{
					__int64 natValue = j->second;
					if(++*reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 6) == 10000)
					{
						ifStruct->NatTable.erase(j);
						j = ifStruct->NatTable.begin();
						continue;
					}
					j->second = natValue;
					++j;
				}

				std::vector<Packet>::iterator k = ifStruct->PacketQueue.begin();
				while(k != ifStruct->PacketQueue.end())
				{
					Packet packet = *k;

					__int64 ifLocalTargetMac = ifStruct->ArpTable[packet.Target];
					u_char *pIfLocalTargetMac = reinterpret_cast<u_char *>(&ifLocalTargetMac);
					if((pIfLocalTargetMac[0] == 0xFF) &&
					   (pIfLocalTargetMac[1] == 0xFF) &&
					   (pIfLocalTargetMac[2] == 0xFF) &&
					   (pIfLocalTargetMac[3] == 0xFF) &&
					   (pIfLocalTargetMac[4] == 0xFF) &&
					   (pIfLocalTargetMac[5] == 0xFF))
					{
						if(*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6]) == 0xFFFF)
						{
							delete [] packet.Data;

							ifStruct->PacketQueue.erase(k);
							k = ifStruct->PacketQueue.begin();
							continue;
						}
					}
					else
					{
						OnListenIp(ifStruct->pAdapter, &packet.Header, packet.Data, true);
						delete [] packet.Data;

						ifStruct->PacketQueue.erase(k);
						k = ifStruct->PacketQueue.begin();
						continue;
					}

					++k;
				}

				ReleaseMutex(ifStruct->hMutex);			
			}
			Sleep(10);
		}
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Error: " << e.what() << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	SetEvent(g_hExitEvent);
	return 0;
}

// ========================================================================================================================

DWORD WINAPI PcapListenThreadProc(LPVOID lpParameter)
{
	try
	{
		pcap_t *pAdapter = reinterpret_cast<pcap_t *>(lpParameter);

		pcap_pkthdr *pPktHeader = NULL;
		const u_char *pPktData = NULL;

		while(WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0)
		{
			int pktResult = pcap_next_ex(pAdapter, &pPktHeader, &pPktData);
			if(pktResult < 0)
			{
				break;
			}
			else if((pktResult == 0) || (pPktHeader->caplen < sizeof(EthernetFrameHeader)))
			{
				continue;
			}

			const EthernetFrameHeader *pktEthernetFrameHeader = reinterpret_cast<const EthernetFrameHeader *>(pPktData);
			switch(pktEthernetFrameHeader->Type)
			{
				case EtherTypeArp:
					if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader)))
					{
						OnListenArp(pAdapter, pPktHeader, const_cast<u_char *>(pPktData));
					}
					break;

				case EtherTypeIp:
					if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader)))
					{
						OnListenIp(pAdapter, pPktHeader, const_cast<u_char *>(pPktData), false);
					}
					break;

				default:
					break;
			}
		}
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Error: " << e.what() << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	SetEvent(g_hExitEvent);
	return 0;
}

// ========================================================================================================================

void OnListenArp(pcap_t *pAdapter, pcap_pkthdr *pPktHeader, u_char *pPktData)
{
	IfStruct *ifStruct = NULL;

	const ArpPacketHeader *pktArpPacketHeader = reinterpret_cast<const ArpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	if(pktArpPacketHeader->Operation == ArpOperationWhoHas)
	{
		for(std::vector<IfStruct *>::iterator i = g_Interfaces.begin(); i != g_Interfaces.end(); ++i)
		{
			if((*i)->Ip == pktArpPacketHeader->TargetProtocolAddress)
			{
				ifStruct = (*i);
				break;
			}
		}

		if(ifStruct != NULL)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << "<< ARP WHO-HAS " << ((ifStruct->Ip & 0x000000FF)) << "."
										   << ((ifStruct->Ip & 0x0000FF00) >> 8) << "."
										   << ((ifStruct->Ip & 0x00FF0000) >> 16) << "."
										   << ((ifStruct->Ip & 0xFF000000) >> 24) << " TELL "
										   << ((pktArpPacketHeader->SenderProtocolAddress & 0x000000FF)) << "."
										   << ((pktArpPacketHeader->SenderProtocolAddress & 0x0000FF00) >> 8) << "."
										   << ((pktArpPacketHeader->SenderProtocolAddress & 0x00FF0000) >> 16) << "."
										   << ((pktArpPacketHeader->SenderProtocolAddress & 0xFF000000) >> 24) << " "
										   << std::hex
										   << std::setfill('0')
										   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[0]) << ":"
										   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[1]) << ":"
										   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[2]) << ":"
										   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[3]) << ":"
										   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[4]) << ":"
										   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[5])
										   << std::dec << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);

			const u_int arpRespPktMemSize = (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));
			u_char *arpRespPktData = new u_char[arpRespPktMemSize];

			EthernetFrameHeader *arpRespPktEthernetFrameHeader = reinterpret_cast<EthernetFrameHeader *>(arpRespPktData);
			SecureZeroMemory(arpRespPktEthernetFrameHeader, sizeof(EthernetFrameHeader));
			RtlCopyMemory(&arpRespPktEthernetFrameHeader->SourceMac, &ifStruct->Mac, 6);
			RtlCopyMemory(&arpRespPktEthernetFrameHeader->DestinationMac, &pktArpPacketHeader->SenderHardwareAddress, 6);
			arpRespPktEthernetFrameHeader->Type = EtherTypeArp;

			ArpPacketHeader *arpRespPktArpPacketHeader = reinterpret_cast<ArpPacketHeader *>(arpRespPktData + sizeof(EthernetFrameHeader));
			SecureZeroMemory(arpRespPktArpPacketHeader, sizeof(ArpPacketHeader));
			arpRespPktArpPacketHeader->HardwareAddressSpace = 0x0100;
			arpRespPktArpPacketHeader->ProtocolAddressSpace = 0x0008;
			arpRespPktArpPacketHeader->HardwareAddressLength = 0x06;
			arpRespPktArpPacketHeader->ProtocolAddressLength = 0x04;
			arpRespPktArpPacketHeader->Operation = ArpOperationIsAt;
			RtlCopyMemory(&arpRespPktArpPacketHeader->SenderHardwareAddress, &arpRespPktEthernetFrameHeader->SourceMac, 6);
			RtlCopyMemory(&arpRespPktArpPacketHeader->TargetHardwareAddress, &arpRespPktEthernetFrameHeader->DestinationMac, 6);
			arpRespPktArpPacketHeader->SenderProtocolAddress = ifStruct->Ip;
			arpRespPktArpPacketHeader->TargetProtocolAddress = pktArpPacketHeader->SenderProtocolAddress;

			pcap_sendpacket(pAdapter, arpRespPktData, sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));

			delete [] arpRespPktData;
		}
	}
	else if(pktArpPacketHeader->Operation == ArpOperationIsAt)
	{
		for(std::vector<IfStruct *>::iterator i = g_Interfaces.begin(); i != g_Interfaces.end(); ++i)
		{
			if(RtlEqualMemory(&(*i)->Mac, &pktArpPacketHeader->TargetHardwareAddress, 6))
			{
				ifStruct = (*i);
				break;
			}
		}

		if(ifStruct != NULL)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << "<< ARP " << ((pktArpPacketHeader->SenderProtocolAddress & 0x000000FF)) << "."
								   << ((pktArpPacketHeader->SenderProtocolAddress & 0x0000FF00) >> 8) << "."
								   << ((pktArpPacketHeader->SenderProtocolAddress & 0x00FF0000) >> 16) << "."
								   << ((pktArpPacketHeader->SenderProtocolAddress & 0xFF000000) >> 24) << " IS-AT "
								   << std::hex
								   << std::setfill('0')
								   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[0]) << ":"
								   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[1]) << ":"
								   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[2]) << ":"
								   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[3]) << ":"
								   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[4]) << ":"
								   << std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[5])
								   << std::dec << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);

			u_int arpIpIsAt = pktArpPacketHeader->SenderProtocolAddress;
			__int64 arpMacIsAt;
			RtlCopyMemory(&arpMacIsAt, pktArpPacketHeader->SenderHardwareAddress, 6);
			RtlFillMemory(reinterpret_cast<u_char *>(&arpMacIsAt) + 6, 2, 0xFF);

			if(WaitForSingleObject(ifStruct->hMutex, 2500) != WAIT_OBJECT_0)
			{
				throw std::exception("WaitForSingleObject(ifStruct->hMutex) Failed.");
			}
			ifStruct->ArpTable[arpIpIsAt] = arpMacIsAt;
			ReleaseMutex(ifStruct->hMutex);
		}
	}
}

// ========================================================================================================================

void OnListenIp(pcap_t *pAdapter, pcap_pkthdr *pPktHeader, u_char *pPktData, bool bReuseData)
{
	IfStruct *inIfStruct = NULL;
	IfStruct *outIfStruct = NULL;

	EthernetFrameHeader *pktEthernetFrameHeader = reinterpret_cast<EthernetFrameHeader *>(pPktData);
	IpPacketHeader *pktIpPacketHeader = reinterpret_cast<IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));

	for(std::vector<IfStruct *>::iterator i = g_Interfaces.begin(); i != g_Interfaces.end(); ++i)
	{
		if(RtlEqualMemory(&(*i)->Mac, &pktEthernetFrameHeader->DestinationMac, 6))
		{
			inIfStruct = (*i);
			outIfStruct = inIfStruct->Route;
			break;
		}
	}

	if((inIfStruct == NULL) || (outIfStruct == NULL))
	{
		return;
	}

	u_char *pPktDataCopy = pPktData;
	if(!bReuseData)
	{
		pPktDataCopy = new u_char[pPktHeader->caplen + 1];
		SecureZeroMemory(pPktDataCopy, pPktHeader->caplen + 1);
		RtlCopyMemory(pPktDataCopy, pPktData, pPktHeader->caplen);
	}

	pktEthernetFrameHeader = reinterpret_cast<EthernetFrameHeader *>(pPktDataCopy);
	pktIpPacketHeader = reinterpret_cast<IpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader));

	if(g_RouteType == RouteTypeNat)
	{
		if((inIfStruct->bNat) && (pktIpPacketHeader->SourceAddress != outIfStruct->Ip))
		{
			u_int natKey = 0;
			__int64 natValue = 0;

			u_short destinationPort = 0;
			
			*reinterpret_cast<u_int *>(reinterpret_cast<u_char *>(&natValue)) = pktIpPacketHeader->SourceAddress;
			if(pktIpPacketHeader->Protocol == IpProtocolIcmp)
			{
				natKey |= 0x00010000;

				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << "WARNING: NAT Not Implemented For ICMP." << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);
			}
			else if(pktIpPacketHeader->Protocol == IpProtocolTcp)
			{
				natKey |= 0x00020000;

				TcpPacketHeader *pktTcpPacketHeader = reinterpret_cast<TcpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				*reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 4) = pktTcpPacketHeader->SourcePort;

				destinationPort = pktTcpPacketHeader->DestinationPort;
			}
			else if(pktIpPacketHeader->Protocol == IpProtocolUdp)
			{
				natKey |= 0x00040000;

				UdpPacketHeader *pktUdpPacketHeader = reinterpret_cast<UdpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				*reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 4) = pktUdpPacketHeader->SourcePort;

				destinationPort = pktUdpPacketHeader->DestinationPort;
			}

			for(std::map<u_int, __int64>::iterator i = outIfStruct->NatTable.begin(); i != outIfStruct->NatTable.end(); ++i)
			{
				if(RtlEqualMemory(&i->second, &natValue, 6))
				{
					natKey = i->first;
					natValue = i->second;
					break;
				}
			}

			if((natKey & 0x0000FFFF) == 0)
			{
				for(u_int i = 1; i < 0xFFFF; ++i)
				{
					u_int tKey = (natKey & 0xFFFF0000) | (i & 0x0000FFFF);
					if(outIfStruct->NatTable.find(tKey) == outIfStruct->NatTable.end())
					{
						natKey = tKey;
						EnterCriticalSection(&g_ConsoleCriticalSection);
						std::cout << ">> NAT " << ((*reinterpret_cast<u_int *>(reinterpret_cast<u_char *>(&natValue)) & 0x000000FF)) << "."
											   << ((*reinterpret_cast<u_int *>(reinterpret_cast<u_char *>(&natValue)) & 0x0000FF00) >> 8) << "."
											   << ((*reinterpret_cast<u_int *>(reinterpret_cast<u_char *>(&natValue)) & 0x00FF0000) >> 16) << "."
											   << ((*reinterpret_cast<u_int *>(reinterpret_cast<u_char *>(&natValue)) & 0xFF000000) >> 24) << ":"
											   << ntohs(*reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 4)) << " -> "
											   << ((pktIpPacketHeader->DestinationAddress & 0x000000FF)) << "."
											   << ((pktIpPacketHeader->DestinationAddress & 0x0000FF00) >> 8) << "."
											   << ((pktIpPacketHeader->DestinationAddress & 0x00FF0000) >> 16) << "."
											   << ((pktIpPacketHeader->DestinationAddress & 0xFF000000) >> 24) << ":"
											   << ntohs(destinationPort)
											   << std::endl;
						LeaveCriticalSection(&g_ConsoleCriticalSection);
						break;
					}
				}

				if((natKey & 0x0000FFFF) == 0)
				{
					throw std::exception("NAT Translation Table Full.");
				}
			}

			pktIpPacketHeader->SourceAddress = outIfStruct->Ip;
			if(pktIpPacketHeader->Protocol == IpProtocolTcp)
			{
				TcpPacketHeader *pktTcpPacketHeader = reinterpret_cast<TcpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				pktTcpPacketHeader->SourcePort = (natKey & 0x0000FFFF);
			}
			else if(pktIpPacketHeader->Protocol == IpProtocolUdp)
			{
				UdpPacketHeader *pktUdpPacketHeader = reinterpret_cast<UdpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				pktUdpPacketHeader->SourcePort = (natKey & 0x0000FFFF);
			}

			*reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 6) = 0x0000;
			outIfStruct->NatTable[natKey] = natValue;
		}
		else if((outIfStruct->bNat) && (pktIpPacketHeader->SourceAddress != inIfStruct->Ip))
		{
			u_int natKey = 0;
			__int64 natValue = 0;
			
			if(pktIpPacketHeader->Protocol == IpProtocolIcmp)
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << "!! WARNING: NAT Not Implemented For ICMP." << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);

				natKey |= 0x00010000;
			}
			else if(pktIpPacketHeader->Protocol == IpProtocolTcp)
			{
				TcpPacketHeader *pktTcpPacketHeader = reinterpret_cast<TcpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				natKey = pktTcpPacketHeader->DestinationPort;
				natKey |= 0x00020000;
			}
			else if(pktIpPacketHeader->Protocol == IpProtocolUdp)
			{
				UdpPacketHeader *pktUdpPacketHeader = reinterpret_cast<UdpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				natKey = pktUdpPacketHeader->DestinationPort;
				natKey |= 0x00040000;
			}

			if((natKey & 0x0000FFFF) != 0)
			{
				if(inIfStruct->NatTable.find(natKey) != inIfStruct->NatTable.end())
				{
					natValue = inIfStruct->NatTable[natKey];

					if(natValue != 0)
					{
						pktIpPacketHeader->DestinationAddress = *reinterpret_cast<u_int *>(reinterpret_cast<u_char *>(&natValue));

						if(pktIpPacketHeader->Protocol == IpProtocolTcp)
						{
							TcpPacketHeader *pktTcpPacketHeader = reinterpret_cast<TcpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
							pktTcpPacketHeader->DestinationPort = *reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 4);
						}
						else if(pktIpPacketHeader->Protocol == IpProtocolUdp)
						{
							UdpPacketHeader *pktUdpPacketHeader = reinterpret_cast<UdpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
							pktUdpPacketHeader->DestinationPort = *reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 4);
						}
					}

					*reinterpret_cast<u_short *>(reinterpret_cast<u_char *>(&natValue) + 6) = 0x0000;
					inIfStruct->NatTable[natKey] = natValue;
				}
				else
				{
					EnterCriticalSection(&g_ConsoleCriticalSection);
					std::cout << "!! WARNING: Incoming NAT Port Not Known From Host "
							  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << std::endl;
					LeaveCriticalSection(&g_ConsoleCriticalSection);
				}
			}
		}
	}

	u_int ifLocalSenderIp = (((ntohl(pktIpPacketHeader->SourceAddress) ^ ntohl(inIfStruct->Ip)) & ntohl(inIfStruct->Netmask)) == 0) ? pktIpPacketHeader->SourceAddress : inIfStruct->Gateway;
	u_int ifLocalTargetIp = (((ntohl(pktIpPacketHeader->DestinationAddress) ^ ntohl(outIfStruct->Ip)) & ntohl(outIfStruct->Netmask)) == 0) ? pktIpPacketHeader->DestinationAddress : outIfStruct->Gateway;
	
	if(WaitForSingleObject(outIfStruct->hMutex, 2500) != WAIT_OBJECT_0)
	{
		throw std::exception("WaitForSingleObject(outIfStruct->hMutex) Failed.");
	}

	__int64 ifLocalSenderMac = (inIfStruct->ArpTable.find(ifLocalSenderIp) == inIfStruct->ArpTable.end()) ? 0xFFFFFFFFFFFFFFFF : inIfStruct->ArpTable[ifLocalSenderIp];
	u_char *pIfLocalSenderMac = reinterpret_cast<u_char *>(&ifLocalSenderMac);
	if((pIfLocalSenderMac[0] == 0xFF) &&
	   (pIfLocalSenderMac[1] == 0xFF) &&
	   (pIfLocalSenderMac[2] == 0xFF) &&
	   (pIfLocalSenderMac[3] == 0xFF) &&
	   (pIfLocalSenderMac[4] == 0xFF) &&
	   (pIfLocalSenderMac[5] == 0xFF))
	{
		if(*reinterpret_cast<u_short *>(&pIfLocalSenderMac[6]) == 0xFFFF)
		{
			*reinterpret_cast<u_short *>(&pIfLocalSenderMac[6]) = 0x0000;
			inIfStruct->ArpTable[ifLocalSenderIp] = ifLocalSenderMac;
		}
	}

	__int64 ifLocalTargetMac = (outIfStruct->ArpTable.find(ifLocalTargetIp) == outIfStruct->ArpTable.end()) ? 0xFFFFFFFFFFFFFFFF : outIfStruct->ArpTable[ifLocalTargetIp];
	u_char *pIfLocalTargetMac = reinterpret_cast<u_char *>(&ifLocalTargetMac);
	if((pIfLocalTargetMac[0] == 0xFF) &&
	   (pIfLocalTargetMac[1] == 0xFF) &&
	   (pIfLocalTargetMac[2] == 0xFF) &&
	   (pIfLocalTargetMac[3] == 0xFF) &&
	   (pIfLocalTargetMac[4] == 0xFF) &&
	   (pIfLocalTargetMac[5] == 0xFF))
	{
		if(*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6]) == 0xFFFF)
		{
			*reinterpret_cast<u_short *>(&pIfLocalTargetMac[6]) = 0x0000;
			outIfStruct->ArpTable[ifLocalTargetIp] = ifLocalTargetMac;
		}

		Packet queuePacket;
		queuePacket.Target = ifLocalTargetIp;
		queuePacket.Header = *pPktHeader;
		queuePacket.Data = pPktDataCopy;
		outIfStruct->PacketQueue.push_back(queuePacket);

		pPktDataCopy = NULL;
	}

	ReleaseMutex(outIfStruct->hMutex);

	if(pPktDataCopy != NULL)
	{
		RtlCopyMemory(&pktEthernetFrameHeader->DestinationMac, &ifLocalTargetMac, 6);
		RtlCopyMemory(&pktEthernetFrameHeader->SourceMac, &outIfStruct->Mac, 6);

		if(pktIpPacketHeader->TimeToLive-- != 0)
		{
			if(pktIpPacketHeader->Protocol == IpProtocolIcmp)
			{
				IcmpPacketHeader *pktIcmpPacketHeader = reinterpret_cast<IcmpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				u_char *pktIcmpData = reinterpret_cast<u_char *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader));
				
				pktIcmpPacketHeader->Checksum = 0;

				u_int icmpChecksum = 0;
				InitialiseChecksum(icmpChecksum);
				UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(pktIcmpPacketHeader), sizeof(IcmpPacketHeader) / sizeof(u_short));
				UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(pktIcmpData), (ntohs(pktIpPacketHeader->TotalLength) - sizeof(IpPacketHeader) - sizeof(IcmpPacketHeader)) / sizeof(u_short));
				pktIcmpPacketHeader->Checksum = FinaliseChecksum(icmpChecksum);
			}
			else if(pktIpPacketHeader->Protocol == IpProtocolTcp)
			{
				TcpPacketHeader *pktTcpPacketHeader = reinterpret_cast<TcpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
				
				ChecksumPseudoHeader pktChecksumPseudoHeader;
				pktChecksumPseudoHeader.DestinationAddress = pktIpPacketHeader->DestinationAddress;
				pktChecksumPseudoHeader.Length = htons(ntohs(pktIpPacketHeader->TotalLength) - sizeof(IpPacketHeader));
				pktChecksumPseudoHeader.Protocol = pktIpPacketHeader->Protocol;
				pktChecksumPseudoHeader.SourceAddress = pktIpPacketHeader->SourceAddress;
				pktChecksumPseudoHeader.Zero = 0;

				pktTcpPacketHeader->Checksum = 0;

				u_int tcpChecksum = 0;
				InitialiseChecksum(tcpChecksum);
				UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(&pktChecksumPseudoHeader), sizeof(ChecksumPseudoHeader) / sizeof(u_short));
				
				u_int tcpLength = (ntohs(pktIpPacketHeader->TotalLength) - sizeof(IpPacketHeader));
				if((tcpLength % 2) == 1)
				{
					tcpLength++;
				}
				UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(pktTcpPacketHeader), tcpLength / sizeof(u_short));
				pktTcpPacketHeader->Checksum = FinaliseChecksum(tcpChecksum);
			}
			else if(pktIpPacketHeader->Protocol == IpProtocolUdp)
			{
				UdpPacketHeader *pktUdpPacketHeader = reinterpret_cast<UdpPacketHeader *>(pPktDataCopy + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));

				ChecksumPseudoHeader pktChecksumPseudoHeader;
				pktChecksumPseudoHeader.DestinationAddress = pktIpPacketHeader->DestinationAddress;
				pktChecksumPseudoHeader.Length = htons(ntohs(pktIpPacketHeader->TotalLength) - sizeof(IpPacketHeader));
				pktChecksumPseudoHeader.Protocol = pktIpPacketHeader->Protocol;
				pktChecksumPseudoHeader.SourceAddress = pktIpPacketHeader->SourceAddress;
				pktChecksumPseudoHeader.Zero = 0;

				pktUdpPacketHeader->Checksum = 0;

				u_int udpChecksum = 0;
				InitialiseChecksum(udpChecksum);
				UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(&pktChecksumPseudoHeader), sizeof(ChecksumPseudoHeader) / sizeof(u_short));
				
				u_int udpLength = (ntohs(pktIpPacketHeader->TotalLength) - sizeof(IpPacketHeader));
				if((udpLength % 2) == 1)
				{
					udpLength++;
				}
				UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(pktUdpPacketHeader), udpLength / sizeof(u_short));
				pktUdpPacketHeader->Checksum = FinaliseChecksum(udpChecksum);
			}

			pktIpPacketHeader->Crc = 0;
			u_int ipCrc = 0;
			InitialiseChecksum(ipCrc);
			UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
			pktIpPacketHeader->Crc = FinaliseChecksum(ipCrc);

			pcap_sendpacket(outIfStruct->pAdapter, pPktDataCopy, pPktHeader->caplen);
		}
	}

	if(!bReuseData)
	{
		delete [] pPktDataCopy;
	}
}

// ========================================================================================================================

void GenerateInterfaceDefinitions(pcap_if_t *pDeviceList, std::vector<std::string> &ifStrings, std::vector<std::string> &fwdStrings)
{
	for(std::vector<std::string>::iterator i = ifStrings.begin(); i != ifStrings.end(); ++i)
	{
		std::string &parseIf = (*i);

		std::vector<std::string> ifBlocks;
		u_int ifBlockMarker = 0;
		while(!parseIf.empty() && (ifBlockMarker != std::string::npos))
		{
			u_int nextifBlockMarker = parseIf.find(';', ifBlockMarker + 1);
			std::string ifBlock = parseIf.substr(ifBlockMarker + ((ifBlockMarker == 0) ? 0 : 1), nextifBlockMarker - ifBlockMarker - ((ifBlockMarker == 0) ? 0 : 1));
			ifBlockMarker = nextifBlockMarker;
			ifBlocks.push_back(ifBlock);
		}

		if(ifBlocks.size() != 5)
		{
			throw std::exception("Invalid Interface Definition.");
		}

		IfStruct *ifStruct = new IfStruct;
		
		ifStruct->hMutex = NULL;
		ifStruct->hPcapListenThread = NULL;

		ifStruct->pDevice = NULL;
		ifStruct->pAdapter = NULL;

		SecureZeroMemory(&ifStruct->Mac, 6);
		ifStruct->Ip = 0;
		ifStruct->Netmask = 0;
		ifStruct->Gateway = 0;

		ifStruct->Route = NULL;

		ifStruct->bNat = ((g_RouteType == RouteTypeNat) && (g_Interfaces.size() == 0));

		u_int uDeviceEnum = 0;
		u_int uDeviceId = strtol(ifBlocks.at(0).c_str(), NULL, 10);
		
		pcap_if_t *pDeviceEnum = pDeviceList;
		while(pDeviceEnum != NULL)
		{
			if(++uDeviceEnum == uDeviceId)
			{
				std::string targetDeviceName = pDeviceEnum->name;
				size_t npfOffset = targetDeviceName.find("NPF_");
				if(npfOffset == std::string::npos)
				{
					throw std::exception("Device Name Format Not Recognised.");
				}
				targetDeviceName = targetDeviceName.substr(npfOffset + 4);

				u_int uBufferSize = 0;
				if(GetAdaptersInfo(NULL, reinterpret_cast<PULONG>(&uBufferSize)) == ERROR_BUFFER_OVERFLOW)
				{
					PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(new char[uBufferSize]);
					if(GetAdaptersInfo(pAdapterInfo, reinterpret_cast<PULONG>(&uBufferSize)) != ERROR_SUCCESS)
					{
						throw std::exception("GetAdaptersAddresses(pAdapterInfo) Failed.");
					}

					PIP_ADAPTER_INFO pAdapterInfoEnum = pAdapterInfo;
					do
					{
						if(targetDeviceName.compare(pAdapterInfoEnum->AdapterName) == 0)
						{
							ifStruct->pDevice = pDeviceEnum;

							if(ifBlocks.at(1).size() != 0)
							{
								std::string parseMac = ifBlocks.at(1);
								u_int macBlockMarker = 0;
								u_short macIndex = 0;
								while(!parseMac.empty() && (macBlockMarker != std::string::npos) && (macIndex < 6))
								{
									u_int nextMacBlockMarker = parseMac.find(':', macBlockMarker + 1);
									std::string macBlock = parseMac.substr(macBlockMarker + ((macBlockMarker == 0) ? 0 : 1), nextMacBlockMarker - macBlockMarker - ((macBlockMarker == 0) ? 0 : 1));
									macBlockMarker = nextMacBlockMarker;
									ifStruct->Mac[macIndex++] = static_cast<u_char>(strtol(macBlock.c_str(), NULL, 16));
								}
							}
							else
							{
								RtlCopyMemory(ifStruct->Mac, pAdapterInfoEnum->Address, 6);
							}

							if(ifBlocks.at(2).size() != 0)
							{
								ifStruct->Ip = inet_addr(ifBlocks.at(2).c_str());
								if(ifBlocks.at(1).size() == 0)
								{
									*reinterpret_cast<u_int *>(&ifStruct->Mac[2]) ^= ifStruct->Ip;
								}
							}
							else
							{
								ifStruct->Ip = inet_addr(pAdapterInfoEnum->IpAddressList.IpAddress.String);
							}

							if(ifBlocks.at(3).size() != 0)
							{
								ifStruct->Netmask = inet_addr(ifBlocks.at(3).c_str());
							}
							else
							{
								ifStruct->Netmask = inet_addr(pAdapterInfoEnum->IpAddressList.IpMask.String);
							}

							if(ifBlocks.at(4).size() != 0)
							{
								ifStruct->Gateway = inet_addr(ifBlocks.at(4).c_str());
							}
							else
							{
								ifStruct->Gateway = inet_addr(pAdapterInfoEnum->GatewayList.IpAddress.String);
							}

							if((ifStruct->hMutex = CreateMutex(NULL, FALSE, NULL)) == NULL)
							{
								throw std::exception("CreateMutex() Failed.");
							}

							std::cout << "Virtual Interface: "
									  << uDeviceId << " / "
									  << std::hex
									  << std::setfill('0')
									  << std::setw(2) << static_cast<u_short>(ifStruct->Mac[0]) << ":"
									  << std::setw(2) << static_cast<u_short>(ifStruct->Mac[1]) << ":"
									  << std::setw(2) << static_cast<u_short>(ifStruct->Mac[2]) << ":"
									  << std::setw(2) << static_cast<u_short>(ifStruct->Mac[3]) << ":"
									  << std::setw(2) << static_cast<u_short>(ifStruct->Mac[4]) << ":"
									  << std::setw(2) << static_cast<u_short>(ifStruct->Mac[5])
									  << std::dec << " / "
									  << ((ifStruct->Ip & 0x000000FF)) << "."
									  << ((ifStruct->Ip & 0x0000FF00) >> 8) << "."
									  << ((ifStruct->Ip & 0x00FF0000) >> 16) << "."
									  << ((ifStruct->Ip & 0xFF000000) >> 24) << " / "
									  << ((ifStruct->Netmask & 0x000000FF)) << "."
									  << ((ifStruct->Netmask & 0x0000FF00) >> 8) << "."
									  << ((ifStruct->Netmask & 0x00FF0000) >> 16) << "."
									  << ((ifStruct->Netmask & 0xFF000000) >> 24) << " / "
									  << ((ifStruct->Gateway & 0x000000FF)) << "."
									  << ((ifStruct->Gateway & 0x0000FF00) >> 8) << "."
									  << ((ifStruct->Gateway & 0x00FF0000) >> 16) << "."
									  << ((ifStruct->Gateway & 0xFF000000) >> 24) << " "
									  << (ifStruct->bNat ? " / NAT" : "") << std::endl;

							for(std::vector<IfStruct *>::iterator j = g_Interfaces.begin(); j != g_Interfaces.end(); ++j)
							{
								if((*j)->pDevice == ifStruct->pDevice)
								{
									ifStruct->hPcapListenThread = (*j)->hPcapListenThread;
									ifStruct->pAdapter = (*j)->pAdapter;
									break;
								}
							}

							if(ifStruct->hPcapListenThread == NULL)
							{
								char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
								if((ifStruct->pAdapter = pcap_open(ifStruct->pDevice->name,
																   65536,
																   PCAP_OPENFLAG_PROMISCUOUS,
																   1,
																   NULL,
																   pcapErrorBuffer)) == NULL)
								{
									throw std::exception("pcap_open() Failed.");
								}

								if((ifStruct->hPcapListenThread = CreateThread(NULL, 0, PcapListenThreadProc, ifStruct->pAdapter, 0, NULL)) == NULL)
								{
									throw std::exception("CreateThread() Failed.");
								}
							}
							break;
						}
					}
					while(pAdapterInfoEnum = pAdapterInfoEnum->Next);
					delete [] pAdapterInfo;

					if(pAdapterInfoEnum == NULL)
					{
						throw std::exception("Unable to Match Winpcap Device To Windows Device.");
					}
				}
				break;
			}
			pDeviceEnum = pDeviceEnum->next;
		}
		if((pDeviceEnum == NULL) || (ifStruct->pDevice == NULL))
		{
			throw std::exception("Winpcap Device Not Found.");
		}

		g_Interfaces.push_back(ifStruct);
	}

	g_Interfaces.at(0)->Route = g_Interfaces.at(1);
	g_Interfaces.at(1)->Route = g_Interfaces.at(0);

	std::cout << std::endl;
}

// ========================================================================================================================

void PrintUsage()
{
	std::cout << "Usage: Droute.exe /Nat /Fwd:???" << std::endl
			  << "       <Device>;<Mac>;<Ip>;<Netmask>;<Gateway> <Device>;<Mac>;<Ip>;<Netmask>;<Gateway>" << std::endl
			  << std::endl
			  << "Available Devices:" << std::endl << std::endl;

	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *pDeviceList = NULL;

	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pDeviceList, pcapErrorBuffer) == -1)
	{
		std::cout << "Error: pcap_findalldevs_ex() Failed." << std::endl;
	}
	else
	{
		pcap_if_t *pDeviceEnum = pDeviceList;
		int deviceEnumCount = 0;
		while(pDeviceEnum != NULL)
		{
			std::cout << "  " << ++deviceEnumCount << ". " << pDeviceEnum->description << std::endl;
			pDeviceEnum = pDeviceEnum->next;
		}

		if(pDeviceList != NULL)
		{
			pcap_freealldevs(pDeviceList);
			pDeviceList = NULL;
		}
	}
	std::cout << std::endl;
}

// ========================================================================================================================
