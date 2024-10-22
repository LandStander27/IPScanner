#ifndef _WIN32
	#define LINUX
#else
	#define WINDOWS
#endif

#define RECV_TIMEOUT 100

#ifdef LINUX

#include <logger.hpp>

#include <chrono>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <cstring>
#include <climits>
#include <cerrno>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <cstdlib>
#include <linux/if_arp.h>
#include <cstdio>

void clear_arp_cache() {
	log_info("Running \"ip -s -s neigh flush all > /dev/null\"\n");
	int ret;
	if ((ret = system("ip -s -s neigh flush all > /dev/null")) < 0) {
		log_panic("Could not run command \"ip -s -s neigh flush all > /dev/null\"");
	} else if (!WIFEXITED(ret)) {
		log_panic("Could not clear arp cache");
	} else if (WEXITSTATUS(ret) != 0) {
		exit(WEXITSTATUS(ret));
	}
}

int read_nl_sock(int socket, char *buf, unsigned int seq, unsigned int pid) {
	struct nlmsghdr *nl_hdr;
	int read_len = 0, msg_len = 0;
	do {
		if((read_len = recv(socket, buf, 8192 - msg_len, 0)) < 0) {
			log_panic("recv failed");
			return -1;
		}
		nl_hdr = (struct nlmsghdr *)buf;
		if((NLMSG_OK(nl_hdr, read_len) == 0) || (nl_hdr->nlmsg_type == NLMSG_ERROR)) {
			log_panic("error in packet");
			return -1;
		}
		if (nl_hdr->nlmsg_type == NLMSG_DONE) {
			break;
		}
		
		buf += read_len;
		msg_len += read_len;
		
		if ((nl_hdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			break;
		}
	} while((nl_hdr->nlmsg_seq != seq) || (nl_hdr->nlmsg_pid != pid));
	
	return msg_len;
}

void get_source(char* buffer) {
	struct nlmsghdr *nl_msg;
	// struct route_info rt_info;
	char msg_buf[8192];
	
	int seq = 0;
	
	auto temp = socket;
	int socket = temp(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (socket < 0) {
		log_panic("Could not create socket");
	}
	
	memset(msg_buf, 0, sizeof(msg_buf));
	nl_msg = (struct nlmsghdr *)msg_buf;
	
	nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
	nl_msg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

	nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nl_msg->nlmsg_seq = seq++; // Sequence of the message packet.
	nl_msg->nlmsg_pid = getpid(); // PID of process sending the request.
	
	if(send(socket, nl_msg, nl_msg->nlmsg_len, 0) < 0) {
		log_panic("send failed");
	}
	
	int len;
	
	if((len = read_nl_sock(socket, msg_buf, seq, getpid())) < 0) {
		log_panic("read_nl_socket failed");
	}
	
	for (; NLMSG_OK(nl_msg, len); nl_msg = NLMSG_NEXT(nl_msg, len)) {
		// memset(&rt_info, 0, sizeof(struct route_info));
		struct rtmsg* rt_msg = (struct rtmsg*)NLMSG_DATA(nl_msg);
		if ((rt_msg->rtm_family != AF_INET) || (rt_msg->rtm_table != RT_TABLE_MAIN)) {
			continue;
		}
		
		struct rtattr* rt_attr = (struct rtattr*)RTM_RTA(rt_msg);
		int rt_len = RTM_PAYLOAD(nl_msg);
		int dst = 0;
		for (; RTA_OK(rt_attr, rt_len); rt_attr = RTA_NEXT(rt_attr, rt_len)) {
			switch(rt_attr->rta_type) {
				case RTA_OIF:
					if_indextoname(*(int *)RTA_DATA(rt_attr), buffer);
					break;
				// case RTA_PREFSRC:
				// 	source_ip = *(u_int *)RTA_DATA(rt_attr);
				case RTA_DST:
					dst = *(u_int*)RTA_DATA(rt_attr);
					break;
				default:
					break;
            }
		}
		if (dst == 0) {
			return;
		}
	}
}

char* get_mac(int ip[]) {

	FILE* file;
	if ((file = fopen("/proc/net/arp", "r")) == NULL) {
		log_panic("Could not open /proc/net/arp");
	}
	
	char line[200];
	char read_ip[100];
	int type, flags;
	char hwa[100];
	char mask[100];
	char dev[100];

	if (fgets(line, sizeof(line), file) == (char*)NULL) {
		log_panic("Could not read /proc/net/arp");
	}
	
	while (fgets(line, sizeof(line), file) != (char*)NULL) {
		int num = sscanf(line, "%s 0x%x 0x%x %99s %99s %99s\n", read_ip, &type, &flags, hwa, mask, dev);
		if (num <= 5) {
			break;
		}
		
		if (!strcmp("00:00:00:00:00:00", hwa)) {
			continue;
		}

		if (!strcmp(read_ip, std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]).c_str())) {
			log_debug("mac, ip, valid: %s, %s, %d\n", hwa, read_ip, !(!strcmp("00:00:00:00:00:00", hwa)));
			char* str = (char*)malloc(sizeof(char)*18);
			strcpy(str, hwa);
			fclose(file);
			return str;
		}
		
	}
	
	fclose(file);
	return NULL;
}

struct ICMPHeader {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
};

struct ICMPEchoMessage : ICMPHeader {
	uint16_t id;
	uint16_t seq;
	uint8_t data[64];
};

struct ICMPResponse {
	unsigned char buffer[1024];
	ICMPHeader header;
};

template <class T>
static uint16_t checksum(T &packet) {
	uint16_t *element = reinterpret_cast<uint16_t *>(&packet);
	unsigned long size = sizeof(T);
	uint32_t sum = 0;
	for (; size > 1; size -= 2) {
		sum += *element++;
	}
	if (size > 0) {
		sum += *reinterpret_cast<uint8_t *>(element);
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	packet.checksum = static_cast<uint16_t>(~sum);
	return packet.checksum;
};

long long ping(int ip[]) {
	
	auto temp = socket;
	int socket = temp(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (socket <= 0) {
		log_panic("Could not create socket");
	}
	
	unsigned char ttl = 255;
	if (setsockopt(socket, SOL_IP, IP_TTL, (char*)&ttl, sizeof(ttl)) != 0) {
		log_panic("Could not set socket TTL");
	}
	
	int flags = fcntl(socket, 3, 0);
	if ((flags == -1) || fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_panic("Could not set socket options");
	}
	
	ICMPEchoMessage request;
	memset(&request, 0, sizeof(ICMPEchoMessage));
	request.id = rand() % USHRT_MAX;
	request.type = 8;
	request.seq = 1;
	checksum<ICMPEchoMessage>(request);

	sockaddr address;
	memset(&address, 0, sizeof(sockaddr_in));
	reinterpret_cast<sockaddr_in *>(&address)->sin_family = AF_INET;
	if (inet_pton(AF_INET, std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]).c_str(), &reinterpret_cast<sockaddr_in *>(&address)->sin_addr) <= 0) {
		log_panic("Internal error");
		close(socket);
		return -2;
	}
	
	log_debug("sendto %d.%d.%d.%d.\n", ip[0], ip[1], ip[2], ip[3]);
	int bytes = sendto(socket, (char*)(&request), sizeof(ICMPEchoMessage), 0, &address, sizeof(sockaddr_in));
	if (bytes == -1) {
		log_info("sendto failed: %d.\n", errno);
		close(socket);
		return -2;
	}
	
	ICMPResponse response;
	memset(&response.buffer, 0, sizeof(unsigned char)*sizeof(response.buffer));
	
	auto start = std::chrono::high_resolution_clock::now();
	
	fd_set sock_set;
	FD_ZERO(&sock_set);
	FD_SET(socket, &sock_set);
	
	timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 1000 * RECV_TIMEOUT;
	
	int activity = select(socket + 1, &sock_set, NULL, NULL, &timeout);
	if ((activity <= 0) | !FD_ISSET(socket, &sock_set)) {
		log_info("select failed: %d.\n", errno);
		close(socket);
		return -2;
	}
	
	unsigned int socklen = sizeof(sockaddr_in);

	while (true) {
		bytes = recvfrom(socket, reinterpret_cast<char*>(response.buffer), sizeof(response.buffer), 0, &address, &socklen);
		if (bytes <= 0) {
			log_info("recvfrom failed: %d.\n", errno);
			return -2;
		}

		ICMPEchoMessage packet;
		memset(&packet, 0, sizeof(ICMPEchoMessage));
		memcpy(&packet, &response.buffer[20], static_cast<long unsigned>(socklen) - 20 > sizeof(ICMPEchoMessage) ? sizeof(ICMPEchoMessage) : static_cast<long unsigned>(socklen) - 20);
		if (packet.id != request.id) {
			continue;
		}
		break;
	}
	close(socket);

	auto end = std::chrono::high_resolution_clock::now();
	unsigned delta = static_cast<unsigned>(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
	if (delta >= RECV_TIMEOUT) {
		return -1;
	}
	
	if (sizeof(ICMPHeader) > socklen) {
		log_info("Incorrect ICMP packet size\n");
		return -2;
	}
	
	ICMPHeader packet;
	memset(&packet, 0, sizeof(ICMPHeader));
	memcpy(&packet, &response.buffer[20], static_cast<long unsigned>(socklen) - 20 > sizeof(ICMPHeader) ? sizeof(ICMPHeader) : static_cast<long unsigned>(socklen) - 20);
	
	switch (packet.type) {
		case 0:
			return delta;
		case 8:
			log_info("Recieved ECHO_REQUEST, assuming local device\n");
			return -3;
		case 11:
			return -1;
		default:
			log_debug("ICMP packet type: %d.\n", packet.type);
			return -2;
	}

	if (packet.type == 11) {
		return -1;
	}
	
	return 0;
}

#endif