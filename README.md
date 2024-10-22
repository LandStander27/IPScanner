# IPScanner
- Program made for Windows and Linux that scans your local subnet.
- Gets the MAC Address of devices that do not respond from ping.
- Zero dependencies.

## Usage
### Downloading
1. Download from the latest release.
### Building
#### Linux for Windows
1. Install MinGW for your distro.
2. `make windows`
3. Binary is in `./bin/ip_scanner.exe`
#### Linux for Linux
1. Install GCC/G++ for your distro.
2. `make build`
3. Binary is in `./bin/ip_scanner`