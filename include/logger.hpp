#pragma once

#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <mutex>

enum LogLevel {
	Debug = 0,
	Info = 1,
	Error = 2,
};

extern LogLevel log_level;
extern std::mutex stdout_lock;

void set_log_level(LogLevel new_level);

#define DEBUG

#ifdef DEBUG
inline void log_debug(const char* format, ...) {
	if (log_level > LogLevel::Debug) {
		return;
	}
	stdout_lock.lock();
	printf("DEBUG: ");
	
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	stdout_lock.unlock();
}

inline void log_info(const char* format, ...) {
	if (log_level > LogLevel::Info) {
		return;
	}
	stdout_lock.lock();
	printf("INFO: ");
	
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	stdout_lock.unlock();
}

inline void log_error(const char* format, ...) {
	if (log_level > LogLevel::Error) {
		return;
	}
	stdout_lock.lock();
	fprintf(stderr, "ERROR: ");
	
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	stdout_lock.unlock();
}

inline void log_panic(const char* format, ...) {
	stdout_lock.lock();
	fprintf(stderr, "PANIC: ");
	
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	
	exit(1);
}
#else
inline void log_debug(const char* format, ...) { }
inline void log_info(const char* format, ...) { }
inline void log_error(const char* format, ...) { }
inline void log_panic(const char* format, ...) { }
#endif