.PHONY: all build clean

all:
	make build

build:
	mkdir -p bin
	g++ -Wall -static-libgcc -static -std=c++20 -o bin/ip_scanner src/*.cpp -I ./include
	
windows:
	mkdir -p bin
	x86_64-w64-mingw32-g++ -Wall -static-libgcc -static -o bin/ip_scanner src/*.cpp -I ./include -liphlpapi -lws2_32

run:
	./bin/ip_scanner

clean:
	rm -rf bin