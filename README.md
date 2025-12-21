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
- glibc 2.36+ (for `arc4random`), or BSD/macOS
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
| `SNIFFDET_BUILD_TESTS` | ON | Build the test suite |
| `SNIFFDET_ENABLE_SANITIZERS` | OFF | Enable AddressSanitizer and UBSan |
| `CMAKE_BUILD_TYPE` | Release | Build type (Debug, Release, RelWithDebInfo) |

### Development Builds

Debug builds automatically use paths within the source/build tree:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
./src/sniffdet --help   # Uses sniffdet.conf-debug and build/src/plugins/
```

No need to specify `-c` or `-p` flags during development.

### Configuration File Search Path

sniffdet follows the XDG Base Directory specification for config files:

1. `$XDG_CONFIG_HOME/sniffdet/sniffdet.conf` (usually `~/.config/sniffdet/`)
2. `/etc/sniffdet/sniffdet.conf`
3. Compiled default (varies by build type)

Example with sanitizers enabled:

```bash
cmake -DSNIFFDET_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug ..
```

### IDE Support

The build generates `compile_commands.json` for clangd and other tools.
For VS Code, install the clangd extension and it will work automatically.

### Testing

The project uses CMocka for unit testing. Tests are built by default.

```bash
# Run all tests
cd build
ctest --output-on-failure

# Or run test binaries directly
./tests/unit/test_helpers
./tests/unit/test_util
```

To skip building tests:
```bash
cmake -DSNIFFDET_BUILD_TESTS=OFF ..
```

**Note**: CMocka is auto-detected. Install via package manager (`libcmocka-devel`
on Fedora, `libcmocka-dev` on Debian) for faster builds, or let CMake download
it automatically via FetchContent.

### Integration Tests

Integration tests verify sniffdet's detection capabilities using a virtual
network (veth pair) and Python-based responders that simulate vulnerable hosts.

```bash
# Run integration tests (requires root)
sudo python3 tests/integration/run_tests.py --build-dir build

# Run specific tests
sudo python3 tests/integration/run_tests.py --build-dir build --tests icmp,arp

# Via CTest (labels: integration, requires_root)
cd build
sudo ctest -L integration --output-on-failure
```

**Requirements**:
- Root privileges (CAP_NET_ADMIN + CAP_NET_RAW)
- Python 3.6+
- Optional: CAP_SYS_ADMIN for network namespace support (enables negative tests)

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
