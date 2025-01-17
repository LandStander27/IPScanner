.PHONY: all build clean
version := $(shell ( set -o pipefail; git describe --long --abbrev=7 2>/dev/null | sed 's/\([^-]*-g\)/r\1/;s/-/./g' || printf "r%s.%s" "$$(git rev-list --count HEAD)" "$$(git rev-parse --short=7 HEAD)"))
	
all:
	make build
	make windows
	chown -R $(shell stat -c "%u:%g" .) ./bin

build:
	sed -i "s/version = .*;/version = \"$(version)\";/" include/info.hpp

	mkdir -p bin
	g++ -Wall -static-libgcc -static -std=c++20 -o bin/ip_scanner src/*.cpp -I ./include
	strip ./bin/ip_scanner
	
windows:
	sed -i "s/version = .*;/version = \"$(version)\";/" include/info.hpp

	mkdir -p bin
	x86_64-w64-mingw32-g++ -Wall -static-libgcc -static -o bin/ip_scanner src/*.cpp -I ./include -liphlpapi -lws2_32

docker:
	docker build -t builder .
	docker run -h builder --name builder --rm -v .:/mnt builder
	docker image rm builder

run:
	./bin/ip_scanner

clean:
	rm -rf bin