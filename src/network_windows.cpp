#ifndef _WIN32
	#define LINUX
#else
	#define WINDOWS
#endif

#define RECV_TIMEOUT 20

#ifdef WINDOWS

#include <logger.hpp>

#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <netioapi.h>
#include <windows.h>

// void get_adapters() {
// 	log_debug("Allocating IP_ADDRESSES\n");
	
// 	long unsigned int len = 15000;
// 	IP_ADAPTER_ADDRESSES* addresses = (IP_ADAPTER_ADDRESSES*)malloc(len);
// 	if (addresses == NULL) {
// 		log_panic("Memory alloc failed\n");
// 	}
// 	while (true) {
// 		long unsigned int ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &len);
// 		if (ret == ERROR_BUFFER_OVERFLOW) {
// 			free(addresses);
// 			addresses = NULL;
// 		} else if (ret == ERROR_NO_DATA) {
// 			log_error("No addresses found within parameters.\n");
// 			exit(1);
// 		} else if (ret != NO_ERROR) {
// 			log_panic("GetAdaptersAddresses failed: %d\n", ret);
// 		} else {
// 			break;
// 		}
// 	}
// 	log_info("Got adapter addresses\n");
// 	printf("Subnet mask: %d\n", addresses->FirstUnicastAddress->OnLinkPrefixLength);
// 	print_each("Addresses", addresses->FirstUnicastAddress->Address.lpSockaddr->sa_data, 14, "%u");
// 	// printf("Address: ");
// 	// for (int i = 0; i < 14; i++) {
// 	// 	printf("%u\n", addresses->FirstUnicastAddress->Address.lpSockaddr->sa_data[i]);
// 	// }
	
// 	free(addresses);
// }

char* get_mac(int ip[]) {
	
	IN_ADDR in_addr = IN_ADDR{ { (unsigned char)ip[0], (unsigned char)ip[1], (unsigned char)ip[2], (unsigned char)ip[3] } };
	
	unsigned int mac_addr[2];
	unsigned int len = 6;
	memset(&mac_addr, 0xff, sizeof (mac_addr));
	int ret_val = SendARP(*(IPAddr*)&in_addr, (IPAddr)0, &mac_addr, (PULONG)&len);
	if (ret_val != NO_ERROR) {
		log_info("SendARP to %d.%d.%d.%d failed: %d\n", ip[0], ip[1], ip[2], ip[3], ret_val);
		return NULL;
	} else if (len == 0) {
		log_info("SendARP completed successfully, but returned length = 0");
		return NULL;
	}

	unsigned char* phys_addr = (unsigned char*)&mac_addr;
	char* str = (char*)malloc(sizeof(char)*18);
	// return phys_addr;
	for (int i = 0; i < len; i++) {
		if (i == (len-1)) {
			sprintf(str+i*3, "%.2X", (int)phys_addr[i]);
		} else {
			sprintf(str+i*3, "%.2X:", (int)phys_addr[i]);
		}
	}
	str[17] = 0;
	log_debug("%s\n", str);
	return str;
}

long long ping(HANDLE handle, int ip[]) {
	IN_ADDR in_addr = IN_ADDR{ { (unsigned char)ip[0], (unsigned char)ip[1], (unsigned char)ip[2], (unsigned char)ip[3] } };
	char* data[32] = { 0 };
	
	const int reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(data);
	char* reply_buffer[reply_size] = { 0 };

	int ret_val = IcmpSendEcho(handle, *(IPAddr*)&in_addr, (void*)data, 32, NULL, reply_buffer, reply_size, RECV_TIMEOUT);
	if (ret_val == 0 && GetLastError() == 11010) {
		log_info("%d:%d:%d:%d timed out\n", ip[0], ip[1], ip[2], ip[3]);
		return -1;
	} else if (ret_val == 0) {
		log_panic("IcmpSendEcho failed: %d\n", GetLastError());
		return -2;
	}
	PICMP_ECHO_REPLY echo_reply = (PICMP_ECHO_REPLY)reply_buffer;
	IN_ADDR reply_addr;
	reply_addr.S_un.S_addr = echo_reply->Address;
	log_debug("%s %dms\n", inet_ntoa(reply_addr), echo_reply->RoundTripTime);
	return echo_reply->RoundTripTime;
	// while (true) {
	// 	int ret_val = IcmpSendEcho(handle, *(IPAddr*)&in_addr, (void*)data, 32, NULL, reply_buffer, reply_size, 20);
	// 	if (ret_val == 0) {
	// 		log_panic("IcmpSendEcho failed: %d\n", GetLastError());
	// 	}
	// 	PICMP_ECHO_REPLY echo_reply = (PICMP_ECHO_REPLY)reply_buffer;
	// 	IN_ADDR reply_addr;
	// 	reply_addr.S_un.S_addr = echo_reply->Address;
	// 	log_debug("%s %dms\n", inet_ntoa(reply_addr), echo_reply->RoundTripTime);
	// 	Sleep(1000);
	// }
	
}

#endif