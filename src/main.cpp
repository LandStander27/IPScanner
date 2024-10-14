// C std includes
#include <algorithm>
#include <cstdlib>
#include <errhandlingapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

// C++ std includes
#include <synchapi.h>
#include <vector>
#include <string>
#include <sstream>
#include <thread>

// windows includes
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <netioapi.h>
#include <windows.h>

// local includes
#include <logger.hpp>
#include <argparse/argparse.hpp>

#define print_each(name, arr, len, format) printf("%s - { ", name); for (int some_rand_name = 0; some_rand_name < len-1; some_rand_name++) { printf(format, arr[some_rand_name]); printf(", "); }; printf(format, arr[len-1]);; printf(" }\n");

void get_adapters() {
	log_debug("Allocating IP_ADDRESSES\n");
	
	long unsigned int len = 15000;
	IP_ADAPTER_ADDRESSES* addresses = (IP_ADAPTER_ADDRESSES*)malloc(len);
	if (addresses == NULL) {
		log_panic("Memory alloc failed\n");
	}
	while (true) {
		long unsigned int ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &len);
		if (ret == ERROR_BUFFER_OVERFLOW) {
			free(addresses);
			addresses = NULL;
		} else if (ret == ERROR_NO_DATA) {
			log_error("No addresses found within parameters.\n");
			exit(1);
		} else if (ret != NO_ERROR) {
			log_panic("GetAdaptersAddresses failed: %d\n", ret);
		} else {
			break;
		}
	}
	log_info("Got adapter addresses\n");
	printf("Subnet mask: %d\n", addresses->FirstUnicastAddress->OnLinkPrefixLength);
	print_each("Addresses", addresses->FirstUnicastAddress->Address.lpSockaddr->sa_data, 14, "%u");
	// printf("Address: ");
	// for (int i = 0; i < 14; i++) {
	// 	printf("%u\n", addresses->FirstUnicastAddress->Address.lpSockaddr->sa_data[i]);
	// }
	
	free(addresses);
}

const char* const program_name = "ip_scanner";

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

	int ret_val = IcmpSendEcho(handle, *(IPAddr*)&in_addr, (void*)data, 32, NULL, reply_buffer, reply_size, 20);
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

void extract_nums_from_ip(int nums[], const char* str) {
	unsigned long long i = 0;
	
	std::stringstream ss;
	std::string new_str = std::string(str);
	std::replace(new_str.begin(), new_str.end(), '.', ' ');
	ss << new_str;
	std::string temp;
	int found;
	while (!ss.eof()) {
		ss >> temp;
		if (std::stringstream(temp) >> found) {
			nums[i++] = found;
		}
		temp = "";
	}
}

int get_mask(const char* str) {
	std::stringstream ss;
	std::string new_str = std::string(str);
	std::replace(new_str.begin(), new_str.end(), '/', ' ');
	ss << new_str;
	std::string temp;
	int found;
	while (!ss.eof()) {
		ss >> temp;
		std::stringstream(temp) >> found;
		temp = "";
	}
	return found;
}

std::vector<std::array<int, 4>> get_all_valid_ips(int subnet[], int mask) {
	std::vector<std::array<int, 4>> ips;
	
	if (mask == 0) {
		log_panic("cannot have a mask of 0.");
	} else if (mask == 1) {
		std::array<int, 4> current = { subnet[0], 1, 1, 1 };
		for (int i = 1; i <= 254; i++) {
			for (int j = 1; j <= 254; j++) {
				for (int g = 1; g <= 254; g++) {
					current[1] = i;
					current[2] = j;
					current[3] = g;
					ips.push_back(current);
				}
			}
		}
	} else if (mask == 2) {
		std::array<int, 4> current = { subnet[0], subnet[1], 1, 1 };
		for (int i = 1; i <= 254; i++) {
			for (int j = 1; j <= 254; j++) {
				current[2] = i;
				current[3] = j;
				ips.push_back(current);
			}
		}
	} else if (mask == 3) {
		std::array<int, 4> current = { subnet[0], subnet[1], subnet[2], 1 };
		for (int i = 0; i < 254; i++) {
			ips.push_back(current);
			current[3]++;
		}
	} else if (mask == 4) {
		log_panic("cannot have a mask of 32.");
	}
	
	return ips;
}

// const unsigned long long workers = 50;

int main(int argc, char** argv) {
	argparse::ArgumentParser program(program_name);
	
	#ifdef DEBUG
	program.add_argument("-v", "--verbose").help("increase output verbosity").default_value(false).implicit_value(true);
	#endif

	program.add_argument("-o", "--output").help("specify the output file");
	program.add_argument("--csv").help("output as csv").default_value(false).implicit_value(true);
	program.add_argument("-s", "--subnet").help("specify subnet mask (formatted as: 10.250.250.0/24)").required();
	program.add_argument("-b", "--batches").help("how many requests to batch").default_value(50).scan<'i', int>();;
	
	try {
		program.parse_args(argc, argv);
	} catch (const std::exception& err) {
		log_error("%s\n", err.what());
		printf("%s\n", program.help().str().c_str());
		exit(1);
	}
	
	#ifdef DEBUG
	if (program["--verbose"] == true) {
		set_log_level(LogLevel::Debug);
	}
	#endif
	
	log_info("Starting\n");
	
	int subnet[4];
	extract_nums_from_ip(subnet, program.get<std::string>("--subnet").c_str());
	
	std::vector<std::array<int, 4>> ips = get_all_valid_ips(subnet, get_mask(program.get<std::string>("--subnet").c_str())/8);
	// for (auto i : ips) {
	// 	print_each("ip", i, 4, "%d");
	// }

	unsigned long long current = 0;

	std::vector<HANDLE> handles;
	std::vector<std::thread> threads;
	
	unsigned long long workers = program.get<int>("--batches");

	FILE* output_file = stdout;
	if (program.is_used("--output")) {
		output_file = fopen(program.get<std::string>("--output").c_str(), "w");
	}
	
	for (int i = 0; i < workers; i++) {
		handles.push_back(IcmpCreateFile());
	}
	
	if (program["--csv"] == false) {
		fprintf(output_file, "IP   RoundTripTime   MACAddress\n");
		while (current < ips.size()) {
			std::vector<std::pair<long long, char*>> return_values;
			unsigned long long amount = std::min(ips.size()-current, workers);
			return_values.reserve(amount);
			// long long return_values[workers] = { 0 };
			if (current+workers < ips.size()) {
				for (int i = 0; i < workers; i++) {
					std::thread t([](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			} else {
				unsigned long long start = current;
				for (int i = 0; i < ips.size()-start; i++) {
					std::thread t([](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			}
			
			for (auto &i : threads) {
				i.join();
			}
			
			threads.clear();
			
			for (int i = 0; i < amount; i++) {
				fprintf(output_file, "%d.%d.%d.%d", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3]);
				if (return_values[i].first < 0) {
					fprintf(output_file, " N/A ");
				} else {
					fprintf(output_file, " %dms ", return_values[i].first);
				}
				if (return_values[i].second == NULL) {
					fprintf(output_file, "N/A\n");
				} else {
					fprintf(output_file, "%s\n", return_values[i].second);
					free(return_values[i].second);
				}
			}
		}
	} else {
		
		fprintf(output_file, "IP,Round Trip Time,MAC Address\n");
		while (current < ips.size()) {
			std::vector<std::pair<long long, char*>> return_values;
			unsigned long long amount = std::min(ips.size()-current, workers);
			return_values.reserve(amount);
			// long long return_values[workers] = { 0 };
			if (current+workers < ips.size()) {
				for (int i = 0; i < workers; i++) {
					std::thread t([](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			} else {
				unsigned long long start = current;
				for (int i = 0; i < ips.size()-start; i++) {
					std::thread t([](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			}
			
			for (auto &i : threads) {
				i.join();
			}
			
			threads.clear();
			
			for (int i = 0; i < amount; i++) {
				fprintf(output_file, "%d.%d.%d.%d", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3]);
				if (return_values[i].first < 0) {
					fprintf(output_file, ",N/A");
				} else {
					fprintf(output_file, ",%dms", return_values[i].first);
				}
				if (return_values[i].second == NULL) {
					fprintf(output_file, ",N/A\n");
				} else {
					fprintf(output_file, ",%s\n", return_values[i].second);
					free(return_values[i].second);
				}
			}
		}
	}

	for (auto &i: handles) {
		IcmpCloseHandle(i);
	}
	
	if (output_file != stdout) {
		fclose(output_file);
	}
	return 0;
}
