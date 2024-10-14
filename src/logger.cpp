#include <logger.hpp>

LogLevel log_level = LogLevel::Error;
std::mutex stdout_lock;

void set_log_level(LogLevel new_level) {
	log_level = new_level;
}
