# Sniffdet - Remote Sniffer Detection Tool/Library

**I wrote this network security tool as an undergrad in 2002-2003.** In 2025,
I'm modernizing it to explore how C development practices have evolved over
two decades—while keeping the original functionality intact.

The original code used Autotools and depended on the now-extinct libnet 1.0
library. The modernization effort includes:

- Migrating from Autotools to CMake 3.31
- Adopting modern C11 standards and conventions
- Migrate to latest libnet
- Adding support for modern development tools (clangd, sanitizers, testing)
- AI-assisted, educational workflow

If you're interested in the *how* and *why* behind these changes, check out
the git history—the commit messages are written to be educational.

## What It Does

Sniffdet detects machines running in promiscuous mode (i.e., sniffing network
traffic) using several techniques:

- **ICMP Test**: Sends ICMP packets with invalid MAC addresses
- **ARP Test**: Sends ARP requests with bogus MAC addresses
- **DNS Test**: Monitors for suspicious DNS resolution attempts
- **Latency Test**: Measures response time degradation under flood conditions

## Building

### Requirements

- CMake 3.16 or later
- C compiler (GCC, Clang)
- libpcap development headers (`libpcap-devel` on Fedora, `libpcap-dev` on Debian)
- pthreads support

**Note**: libnet 1.0 is vendored in `third_party/libnet/` since it's no longer
available in modern distributions. No external libnet installation is needed.

### Build Instructions

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

Or with Ninja (faster):

```bash
cmake -G Ninja -B build
cmake --build build
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `SNIFFDET_BUILD_CLI` | ON | Build the sniffdet command-line tool |
| `SNIFFDET_ENABLE_SANITIZERS` | OFF | Enable AddressSanitizer and UBSan |
| `CMAKE_BUILD_TYPE` | Release | Build type (Debug, Release, RelWithDebInfo) |

Example with sanitizers enabled:

```bash
cmake -DSNIFFDET_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug ..
```

### IDE Support

The build generates `compile_commands.json` for clangd and other tools.
For VS Code, install the clangd extension and it will work automatically.

## Usage

```bash
# Run with root privileges (required for raw socket access)
sudo ./build/src/sniffdet --help
sudo ./build/src/sniffdet -t icmp,arp TARGET_HOST
```

## Platform Support

- **Linux**: Primary platform, well tested
- **BSD/macOS**: May work but not actively tested

## Authors

- Ademar de Souza Reis Jr. <ademar@ademar.org>
- Milton Soares Filho <milton.soares.filho@gmail.com>

## License

Copyright (c) 2002-2003 Ademar de Souza Reis Jr. and Milton Soares Filho.
Licensed under the GNU GPL version 2. See [COPYING](COPYING) for details.
