#!/usr/bin/env python3
"""
Integration test runner for sniffdet.

This script sets up a virtual network environment and runs sniffdet detection
tests against simulated vulnerable hosts.

Two modes of operation:
1. With CAP_SYS_ADMIN: Uses network namespaces for full isolation, enabling
   both positive detection and negative timeout tests.
2. Without CAP_SYS_ADMIN: Falls back to simple veth pair, only runs positive
   tests (negative tests would have false positives due to kernel responses).

Network topology:
  veth0 (10.0.0.1) <---> veth1 (10.0.0.2) [in namespace if available]
                         (responder runs here)

Requires: Root privileges + CAP_NET_ADMIN + CAP_NET_RAW capabilities.
Optional: CAP_SYS_ADMIN for network namespace support (enables negative tests).

Usage:
    sudo python3 tests/integration/run_tests.py [--build-dir BUILD_DIR]
"""

import argparse
import os
import subprocess
import sys
import time
import signal
from pathlib import Path
from typing import Optional, Tuple, List

# Test configuration
VETH0 = "veth0"
VETH1 = "veth1"
VETH0_IP = "10.0.0.1"
VETH1_IP = "10.0.0.2"
FAKE_TARGET_IP = "10.0.0.99"  # Non-existent IP for negative tests
DNS_TARGET_IP = "10.0.0.10"  # Fake IP for DNS test
NETNS_NAME = "sniffdet_ns"

# Timeouts
TEST_TIMEOUT = 15  # seconds for each test
RESPONDER_STARTUP_DELAY = 0.5  # seconds to wait for responder to start


class TestResult:
    """Represents the result of a single test."""

    def __init__(self, name: str, passed: bool, message: str, duration: float = 0):
        self.name = name
        self.passed = passed
        self.message = message
        self.duration = duration

    def __str__(self):
        status = "PASS" if self.passed else "FAIL"
        if self.message == "SKIPPED":
            status = "SKIP"
        return f"[{status}] {self.name}: {self.message} ({self.duration:.1f}s)"


def check_netns_support() -> bool:
    """Check if network namespace creation is supported."""
    try:
        result = subprocess.run(
            ["ip", "netns", "add", "__test_ns__"],
            capture_output=True, timeout=5
        )
        if result.returncode == 0:
            subprocess.run(["ip", "netns", "del", "__test_ns__"], capture_output=True)
            return True
        return False
    except Exception:
        return False


class NetworkSetup:
    """Manages the veth pair network setup with optional namespace isolation."""

    def __init__(self, use_namespace: bool = True):
        self.use_namespace = use_namespace
        self.created = False
        self.ns_created = False

    def setup(self) -> bool:
        """Create and configure veth pair. Returns True on success."""
        try:
            # Clean up any stale state first
            self._cleanup_stale()

            if self.use_namespace:
                return self._setup_with_namespace()
            else:
                return self._setup_simple()

        except subprocess.CalledProcessError as e:
            print(f"  Failed to setup network: {e.stderr.decode() if e.stderr else str(e)}")
            return False

    def _setup_with_namespace(self) -> bool:
        """Setup with network namespace for full isolation."""
        # Create network namespace
        subprocess.run(
            ["ip", "netns", "add", NETNS_NAME],
            check=True, capture_output=True
        )
        self.ns_created = True

        # Create veth pair
        subprocess.run(
            ["ip", "link", "add", VETH0, "type", "veth", "peer", "name", VETH1],
            check=True, capture_output=True
        )
        self.created = True

        # Move veth1 to the namespace
        subprocess.run(
            ["ip", "link", "set", VETH1, "netns", NETNS_NAME],
            check=True, capture_output=True
        )

        # Configure veth0 in host namespace
        subprocess.run(
            ["ip", "addr", "add", f"{VETH0_IP}/24", "dev", VETH0],
            check=True, capture_output=True
        )
        subprocess.run(
            ["ip", "link", "set", VETH0, "up"],
            check=True, capture_output=True
        )

        # Configure veth1 in sniffdet_ns namespace
        for cmd in [
            ["ip", "netns", "exec", NETNS_NAME, "ip", "addr", "add", f"{VETH1_IP}/24", "dev", VETH1],
            ["ip", "netns", "exec", NETNS_NAME, "ip", "link", "set", VETH1, "up"],
            ["ip", "netns", "exec", NETNS_NAME, "ip", "link", "set", "lo", "up"],
            ["ip", "netns", "exec", NETNS_NAME, "ip", "link", "set", VETH1, "promisc", "on"],
        ]:
            subprocess.run(cmd, check=True, capture_output=True)

        print(f"  Created veth pair with namespace isolation")
        print(f"    Host: {VETH0} ({VETH0_IP})")
        print(f"    {NETNS_NAME}: {VETH1} ({VETH1_IP})")
        return True

    def _setup_simple(self) -> bool:
        """Setup simple veth pair without namespace (fallback mode)."""
        # Create veth pair
        subprocess.run(
            ["ip", "link", "add", VETH0, "type", "veth", "peer", "name", VETH1],
            check=True, capture_output=True
        )
        self.created = True

        # Configure both interfaces
        cmds = [
            ["ip", "addr", "add", f"{VETH0_IP}/24", "dev", VETH0],
            ["ip", "addr", "add", f"{VETH1_IP}/24", "dev", VETH1],
            ["ip", "link", "set", VETH0, "up"],
            ["ip", "link", "set", VETH1, "up"],
            ["ip", "link", "set", VETH1, "promisc", "on"],
        ]
        for cmd in cmds:
            subprocess.run(cmd, check=True, capture_output=True)

        print(f"  Created simple veth pair (no namespace)")
        print(f"    {VETH0} ({VETH0_IP}) <-> {VETH1} ({VETH1_IP})")
        print(f"  NOTE: Negative tests will be skipped (require CAP_SYS_ADMIN)")
        return True

    def _cleanup_stale(self):
        """Clean up any stale veth or namespace from previous runs."""
        subprocess.run(["ip", "netns", "del", NETNS_NAME], capture_output=True)
        subprocess.run(["ip", "link", "del", VETH0], capture_output=True)

    def teardown(self):
        """Remove veth pair and namespace."""
        if self.ns_created:
            subprocess.run(["ip", "netns", "del", NETNS_NAME], capture_output=True)
            print(f"  Removed namespace {NETNS_NAME}")
        elif self.created:
            subprocess.run(["ip", "link", "del", VETH0], capture_output=True)
            print(f"  Removed veth pair")


class ResponderProcess:
    """Manages a responder subprocess."""

    def __init__(self, responder_type: str, iface: str = VETH1, use_namespace: bool = True):
        self.responder_type = responder_type
        self.iface = iface
        self.use_namespace = use_namespace
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        """Start the responder process."""
        script_dir = Path(__file__).parent
        responders_script = script_dir / "responders.py"

        try:
            if self.use_namespace:
                cmd = ["ip", "netns", "exec", NETNS_NAME,
                       sys.executable, str(responders_script), self.responder_type, self.iface]
            else:
                cmd = [sys.executable, str(responders_script), self.responder_type, self.iface]

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            time.sleep(RESPONDER_STARTUP_DELAY)

            # Check if process is still running
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout else ""
                print(f"    Responder failed to start: {output}")
                return False

            return True

        except Exception as e:
            print(f"    Failed to start responder: {e}")
            return False

    def stop(self):
        """Stop the responder process."""
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def run_sniffdet(
    binary: Path,
    test_type: str,
    target_ip: str,
    iface: str = VETH0,
    timeout: int = TEST_TIMEOUT,
    extra_args: Optional[List[str]] = None
) -> Tuple[int, str]:
    """Run sniffdet with the given parameters."""
    cmd = [str(binary), "-i", iface, "-t", test_type, target_ip]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            ["timeout", str(timeout)] + cmd,
            capture_output=True,
            text=True
        )
        output = result.stdout + result.stderr
        return result.returncode, output
    except Exception as e:
        return -1, str(e)


def check_detection(output: str) -> bool:
    """Check if sniffdet output indicates positive detection."""
    output_lower = output.lower()
    detection_indicators = [
        "test finished [ok]",
        "somebody replied",
        "suspect",
        "positive",
    ]
    return any(indicator in output_lower for indicator in detection_indicators)


def test_positive_detection(binary: Path, test_type: str, use_namespace: bool) -> TestResult:
    """Test that sniffdet detects a vulnerable host (responder running)."""
    start_time = time.time()

    target_ip = DNS_TARGET_IP if test_type == "dns" else VETH1_IP

    responder = ResponderProcess(test_type, VETH1, use_namespace)
    if not responder.start():
        return TestResult(
            f"{test_type}_positive",
            False,
            "Failed to start responder",
            time.time() - start_time
        )

    try:
        exit_code, output = run_sniffdet(binary, test_type, target_ip)
        duration = time.time() - start_time
        detected = check_detection(output)

        if detected:
            return TestResult(f"{test_type}_positive", True, "Detection successful", duration)
        else:
            snippet = output[:200].replace('\n', ' ')
            return TestResult(
                f"{test_type}_positive",
                False,
                f"No detection (exit={exit_code}): {snippet}",
                duration
            )
    finally:
        responder.stop()


def test_negative_timeout(binary: Path, test_type: str, use_namespace: bool) -> TestResult:
    """Test that sniffdet times out when no vulnerable host is present."""
    start_time = time.time()

    if not use_namespace:
        # Skip negative tests without namespace isolation
        return TestResult(f"{test_type}_negative", True, "SKIPPED", 0)

    # Use a non-existent IP to avoid kernel auto-responses (ICMP/ARP)
    target_ip = DNS_TARGET_IP if test_type == "dns" else FAKE_TARGET_IP
    exit_code, output = run_sniffdet(binary, test_type, target_ip, timeout=8)
    duration = time.time() - start_time
    detected = check_detection(output)

    if not detected:
        return TestResult(f"{test_type}_negative", True, "Correctly no detection", duration)
    else:
        snippet = output[:200].replace('\n', ' ')
        return TestResult(
            f"{test_type}_negative",
            False,
            f"False positive: {snippet}",
            duration
        )


def run_all_tests(binary: Path, use_namespace: bool, tests: Optional[List[str]] = None) -> List[TestResult]:
    """Run all integration tests and return results."""
    results = []

    if tests is None:
        tests = ["icmp", "arp", "dns"]

    for test_type in tests:
        print(f"\n  Testing {test_type.upper()}...")

        print(f"    Running positive detection test...")
        result = test_positive_detection(binary, test_type, use_namespace)
        results.append(result)
        print(f"    {result}")

        print(f"    Running negative timeout test...")
        result = test_negative_timeout(binary, test_type, use_namespace)
        results.append(result)
        print(f"    {result}")

    return results


def find_sniffdet_binary(build_dir: Optional[Path] = None) -> Optional[Path]:
    """Find the sniffdet binary."""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent

    if build_dir:
        binary = build_dir / "src" / "sniffdet"
        if binary.exists():
            return binary

    candidates = [
        project_root / "build" / "src" / "sniffdet",
        project_root / "cmake-build-debug" / "src" / "sniffdet",
        project_root / "out" / "build" / "src" / "sniffdet",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def main():
    parser = argparse.ArgumentParser(description="Run sniffdet integration tests")
    parser.add_argument("--build-dir", type=Path, help="Path to build directory")
    parser.add_argument("--tests", type=str, help="Comma-separated list of tests (icmp,arp,dns)")
    parser.add_argument("--no-cleanup", action="store_true", help="Don't clean up after tests")
    parser.add_argument("--force-simple", action="store_true", help="Force simple veth (no namespace)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 tests/integration/run_tests.py")
        sys.exit(1)

    print("Sniffdet Integration Tests")
    print("=" * 50)

    binary = find_sniffdet_binary(args.build_dir)
    if not binary:
        print("ERROR: Could not find sniffdet binary")
        print("Build the project first: cmake -B build && cmake --build build")
        sys.exit(1)
    print(f"Using binary: {binary}")

    # Check namespace support
    use_namespace = not args.force_simple and check_netns_support()
    if use_namespace:
        print("Network namespace support: available")
    else:
        print("Network namespace support: not available (negative tests will be skipped)")

    print("\nSetting up network...")
    network = NetworkSetup(use_namespace)
    if not network.setup():
        print("ERROR: Failed to setup network")
        sys.exit(1)

    try:
        tests = None
        if args.tests:
            tests = [t.strip() for t in args.tests.split(",")]

        print("\nRunning tests...")
        results = run_all_tests(binary, use_namespace, tests)

        print("\n" + "=" * 50)
        print("SUMMARY")
        print("=" * 50)

        # Count results (skipped tests don't count as failures)
        passed = sum(1 for r in results if r.passed)
        skipped = sum(1 for r in results if r.message == "SKIPPED")
        failed = sum(1 for r in results if not r.passed and r.message != "SKIPPED")
        total = len(results)

        for result in results:
            print(result)

        print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped (of {total})")

        sys.exit(0 if failed == 0 else 1)

    finally:
        if not args.no_cleanup:
            print("\nCleaning up...")
            network.teardown()


if __name__ == "__main__":
    main()
