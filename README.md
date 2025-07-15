# IPScanner
- Program made for Windows and Linux that scans your local subnet.
- Gets the MAC Address of devices that do not respond from ping.
- Minimal runtime dependencies.

## Usage
### Using my repo (For Arch-based distros)
```sh
# Install pacsync command
sudo pacman -S --needed pacutils

# Add repo
echo "[landware]              
Server = https://repo.kage.sj.strangled.net/landware/x86_64
SigLevel = DatabaseNever PackageNever TrustedOnly" | sudo tee -a /etc/pacman.conf

# Sync repo individually
sudo pacsync landware

# Install like a normal package
sudo pacman -S ipscanner-git
```

### Downloading
1. Go to latest build action at https://codeberg.org/Land/ipscanner/actions.
2. Download the `linux.zip` or `windows.zip` artifact, depending on your platform.
3. The binary is contained in the downloaded zip.

### Building
#### Native

##### Linux for Linux
```sh
# Install deps
# Arch Linux
pacman -S --needed make git gcc

# Clone the repo
git clone https://codeberg.org/Land/ipscanner.git
cd ipscanner

# Build
make build
```

##### Linux for Windows
```sh
# Install deps
# Arch Linux
pacman -S --needed make git mingw-w64-gcc

# Clone the repo
git clone https://codeberg.org/Land/ipscanner.git
cd ipscanner

# Build
make windows
```

#### Docker
```sh
# Install deps
# Arch Linux
pacman -S --needed make git docker

# Setup Docker (skip if you already set it up)
systemctl enable --now docker.socket
usermod -aG docker $(whoami)
reboot

# Clone the repo
git clone https://codeberg.org/Land/ipscanner.git
cd ipscanner

# Build
make docker
```

<!-- 1. Install deps
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
4. Binaries are built to `./bin`. -->