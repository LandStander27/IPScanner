.PHONY: all build clean

all:
	make build

build:
	mkdir -p bin
	x86_64-w64-mingw32-g++ -static-libgcc -static -o bin/ip_scanner src/*.cpp -I ./include -liphlpapi -lws2_32

run:
	./bin/ip_scanner

clean:
	rm -rf bin