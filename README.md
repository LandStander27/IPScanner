# IPScanner
- Program made for Windows and Linux that scans your local subnet.
- Gets the MAC Address of devices that do not respond from ping.
- Zero dependencies.

## Usage
### Downloading
1. Go to latest build action at https://codeberg.org/Land/ipscanner/actions.
2. Download the `linux.zip` or `windows.zip` artifact, depending on your platform.
3. The binary is contained in the downloaded zip.
### Building
#### Native
##### Linux for Windows
1. Install deps
	* Arch Linux: `pacman -S make git mingw-w64-gcc`
2. `git clone https://codeberg.org/Land/ipscanner.git && cd ipscanner`.
3. `make windows`
4. Binary is in `./bin/ip_scanner.exe`
##### Linux for Linux
1. Install deps
	* Arch Linux: `pacman -S make git gcc`
2. `git clone https://codeberg.org/Land/ipscanner.git && cd ipscanner`.
3. `make build`
4. Binary is in `./bin/ip_scanner`

#### Docker
1. Install docker and GNU make.
2. `git clone https://codeberg.org/Land/ipscanner.git && cd ipscanner`.
3. `make docker`.
4. Binaries are built to `./bin`.