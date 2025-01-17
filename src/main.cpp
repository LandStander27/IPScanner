#ifndef _WIN32
	#define LINUX
#include <cstring>
#include <unistd.h>
#else
	#define WINDOWS
#endif

// C std includes
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

// C++ std includes
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <optional>

// windows includes
#ifdef WINDOWS
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <netioapi.h>
#include <windows.h>
#else
// Linux includes
#include <fcntl.h>
#include <netdb.h>
#include <linux/limits.h>
#endif

// local includes
#include <logger.hpp>
#include <info.hpp>
#include <argparse/argparse.hpp>

#ifdef WINDOWS
#include <network_windows.hpp>
#else
#include <network_linux.hpp>
#endif

#define print_each(name, arr, len, format) printf("%s - { ", name); for (int some_rand_name = 0; some_rand_name < len-1; some_rand_name++) { printf(format, arr[some_rand_name]); printf(", "); }; printf(format, arr[len-1]);; printf(" }\n");

const char* const program_name = "ip_scanner";

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

void print(bool csv, std::vector<std::array<int, 4>>& ips, std::vector<std::pair<long long, char*>>& return_values, unsigned long long amount, unsigned long long current, const char* source_mac, FILE* output_file) {
	if (csv) {
		for (unsigned long long i = 0; i < amount; i++) {
			long long msec = return_values[i].first;
			char* mac = return_values[i].second;
			if (msec < 0 && msec != -3) {
				fprintf(output_file, "%d.%d.%d.%d,N/A", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3]);
			} else if (msec == -3) {
				fprintf(output_file, "%d.%d.%d.%d,0ms", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3]);
			} else {
				fprintf(output_file, "%d.%d.%d.%d,%lldms", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3], msec);
			}
			if (msec != -3) {
				if (mac != NULL) {
					fprintf(output_file, ",%s\n", mac);
				} else {
					fprintf(output_file, ",N/A\n");
				}
				free(mac);
			} else {
				fprintf(output_file, ",%s,LOCAL DEVICE\n", source_mac);
			}
		}
	} else {
		for (unsigned long long i = 0; i < amount; i++) {
			long long msec = return_values[i].first;
			char* mac = return_values[i].second;
			if (msec < 0 && msec != -3) {
				fprintf(output_file, "%d.%d.%d.%d N/A ", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3]);
			} else if (msec == -3) {
				fprintf(output_file, "%d.%d.%d.%d 0ms ", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3]);
			} else {
				fprintf(output_file, "%d.%d.%d.%d %lldms ", ips[current-(amount-i)][0], ips[current-(amount-i)][1], ips[current-(amount-i)][2], ips[current-(amount-i)][3], msec);
			}
			if (msec != -3) {
				if (mac != NULL) {
					fprintf(output_file, "%s\n", mac);
				} else {
					fprintf(output_file, "N/A\n");
				}
				free(mac);
			} else {
				fprintf(output_file, "%s <---- LOCAL DEVICE\n", source_mac);
			}
		}
	}
}

#ifdef WINDOWS
void do_it(unsigned long long workers, const char* output, bool do_csv, std::vector<std::array<int, 4>>& ips) {
	unsigned long long current = 0;

	std::vector<HANDLE> handles;
	std::vector<std::thread> threads;

	FILE* output_file = stdout;
	if (output != NULL) {
		output_file = fopen(output, "w");
	}
	char* source_mac = get_local_mac();

	for (unsigned long long i = 0; i < workers; i++) {
		handles.push_back(IcmpCreateFile());
	}

	if (!do_csv) {
		fprintf(output_file, "IP   RoundTripTime   MACAddress\n");
		while (current < ips.size()) {
			std::vector<std::pair<long long, char*>> return_values;
			unsigned long long amount = std::min(ips.size()-current, workers);
			return_values.reserve(amount);
			// long long return_values[workers] = { 0 };
			if (current+workers < ips.size()) {
				for (unsigned long long i = 0; i < workers; i++) {
					std::thread t([source_mac](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
						if (!strcmp(*mac_addr, source_mac)) {
							*ret_value = -3;
						}
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			} else {
				unsigned long long start = current;
				for (unsigned long long i = 0; i < ips.size()-start; i++) {
					std::thread t([source_mac](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
						if (!strcmp(*mac_addr, source_mac)) {
							*ret_value = -3;
						}
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			}
			
			for (auto &i : threads) {
				i.join();
			}
			
			threads.clear();

			print(do_csv, ips, return_values, amount, current, source_mac, output_file);
		}
	} else {
		fprintf(output_file, "IP,Round Trip Time,MAC Address\n");
		while (current < ips.size()) {
			std::vector<std::pair<long long, char*>> return_values;
			unsigned long long amount = std::min(ips.size()-current, workers);
			return_values.reserve(amount);
			// long long return_values[workers] = { 0 };
			if (current+workers < ips.size()) {
				for (unsigned long long i = 0; i < workers; i++) {
					std::thread t([source_mac](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
						if (!strcmp(*mac_addr, source_mac)) {
							*ret_value = -3;
						}
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			} else {
				unsigned long long start = current;
				for (unsigned long long i = 0; i < ips.size()-start; i++) {
					std::thread t([source_mac](HANDLE handle, int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(handle, ip);
						*mac_addr = get_mac(ip);
						if (!strcmp(*mac_addr, source_mac)) {
							*ret_value = -3;
						}
					}, handles[i], ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			}

			for (auto &i : threads) {
				i.join();
			}
			threads.clear();

			print(do_csv, ips, return_values, amount, current, source_mac, output_file);
		}
	}

	free(source_mac);
	
	for (auto &i: handles) {
		IcmpCloseHandle(i);
	}
	
	if (output_file != stdout) {
		fclose(output_file);
	}
}
#else
void do_it(unsigned long long workers, const char* output, bool do_csv, std::vector<std::array<int, 4>>& ips) {
	FILE* output_file = stdout;
	if (output != NULL) {
		output_file = fopen(output, "w");
	}
	
	char interface[16];
	log_info("Getting source MAC address...\n");
	get_source(interface);

	char path[PATH_MAX];
	unsigned long ret;
	if ((ret = snprintf(path, sizeof(path), "/sys/class/net/%s/address", interface)) < 0 && ret >= sizeof(path)) {
		log_panic("snprintf failed");
	}

	FILE* file = fopen(path, "r");
	if (file == NULL) {
		log_panic("Could not open %s", path);
	}
	char source_mac[18];
	if (fgets(source_mac, sizeof(source_mac), file) == (char*)NULL) {
		log_panic("Could not read from %s", path);
	}
	fclose(file);

	clear_arp_cache();

	unsigned long long current = 0;
	std::vector<std::thread> threads;
	
	if (!do_csv) {
		fprintf(output_file, "IP   RoundTripTime   MACAddress\n");
		while (current < ips.size()) {
			std::vector<std::pair<long long, char*>> return_values;
			unsigned long long amount = std::min(ips.size()-current, workers);
			return_values.reserve(amount);
			if (current+workers < ips.size()) {
				for (unsigned long long i = 0; i < workers; i++) {
					std::thread t([](int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(ip);
						std::this_thread::sleep_for(std::chrono::milliseconds(rand()%1100+100));
						*mac_addr = get_mac(ip);
					}, ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			} else {
				unsigned long long start = current;
				for (unsigned long long i = 0; i < ips.size()-start; i++) {
					std::thread t([](int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(ip);
						std::this_thread::sleep_for(std::chrono::milliseconds(rand()%1100+100));
						*mac_addr = get_mac(ip);
					}, ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			}
			
			for (auto &i : threads) {
				i.join();
			}
			
			threads.clear();

			print(do_csv, ips, return_values, amount, current, source_mac, output_file);
		}
	} else {
		fprintf(output_file, "IP,RoundTripTime,MACAddress\n");
		while (current < ips.size()) {
			std::vector<std::pair<long long, char*>> return_values;
			unsigned long long amount = std::min(ips.size()-current, workers);
			return_values.reserve(amount);
			if (current+workers < ips.size()) {
				for (unsigned long long i = 0; i < workers; i++) {
					std::thread t([](int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(ip);
						std::this_thread::sleep_for(std::chrono::milliseconds(rand()%1100+100));
						*mac_addr = get_mac(ip);
					}, ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			} else {
				unsigned long long start = current;
				for (unsigned long long i = 0; i < ips.size()-start; i++) {
					std::thread t([](int ip[], long long* ret_value, char** mac_addr) {
						*ret_value = ping(ip);
						std::this_thread::sleep_for(std::chrono::milliseconds(rand()%1100+100));
						*mac_addr = get_mac(ip);
					}, ips[current++].data(), &return_values[i].first, &return_values[i].second);
					threads.push_back(std::move(t));
				}
			}
			
			for (auto &i : threads) {
				i.join();
			}
			threads.clear();
			
			print(do_csv, ips, return_values, amount, current, source_mac, output_file);
		}
	}
}
#endif

int main(int argc, char** argv) {
	argparse::ArgumentParser program(program_name, version);
	
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

	unsigned long long workers = program.get<int>("--batches");
	std::optional<std::string> output = std::nullopt;
	if (program.is_used("--output")) {
		output = program.get<std::string>("--output");
	}
	const char* actual_output = NULL;
	if (output.has_value()) {
		actual_output = output.value().c_str();
	}
	do_it(workers, actual_output, program.get<bool>("--csv"), ips);

	return 0;
}
