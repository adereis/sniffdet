# How Sniffdet Works

An introduction to network sniffers and the techniques used to detect them.

> **Historical note:** This document was originally written in 2003.
> While the core concepts remain valid, some details may be dated.
> Modern switched networks, encrypted protocols (TLS everywhere), and
> containerized environments have changed the threat landscape significantly.

## What is a Network Sniffer?

Any program that captures data from a network interface is, potentially, a
sniffer. Such applications can be used legitimately by system administrators
to diagnose network problems (e.g., Wireshark, tcpdump), but also by attackers
to intercept data that doesn't belong to them.

A sniffer is typically a **passive** observer—it injects as few packets as
possible into the network. This makes sniffers difficult to detect. We must
exploit OS characteristics and use empirical tests to find them. It's an
arms race: a sophisticated sniffer can detect and evade our tests, so
detection techniques must continuously improve.

### Normal Mode vs Promiscuous Mode

In **normal mode**, a network interface only captures packets addressed to
its own MAC address (plus broadcast/multicast). The interface ignores traffic
between other hosts.

In **promiscuous mode**, the interface captures *all* traffic on the wire,
regardless of destination. This is what sniffers typically need to intercept
communications between other hosts.

> **Note:** On modern switched networks, the switch only sends relevant traffic
> to each port, limiting what a sniffer can see. However, techniques like ARP
> spoofing, port mirroring, or compromising the switch itself can still enable
> network-wide sniffing.

The main goal of sniffdet's tests is to detect whether a machine's network
interface is running in promiscuous mode.

## Detection Methods

There are two general approaches to finding sniffers: **local** and **remote**.

### Local Detection

Directly check if the local interface is in promiscuous mode. This is
deterministic but has significant limitations:

- Requires access to each machine
- Doesn't scale to large networks
- Must trust the machine's environment
- A compromised machine can hide promiscuous mode (rootkits, kernel modules)

### Remote Detection

Probe machines over the network to infer whether they're in promiscuous mode.
This is what sniffdet implements.

Remote tests fall into two categories:

**Passive tests** monitor network traffic for signatures of sniffer behavior.
For example, detecting ARP spoofing attempts where a sniffer pretends to be
the local router.

**Active tests** send specially crafted packets and observe responses that
would only occur if the target is in promiscuous mode. These exploit quirks
in how operating systems handle packets in promiscuous mode.

## Detection Tests Implemented in Sniffdet

### ICMP Test

Send an ICMP Echo Request (ping) with a **bogus MAC address** to the target.

- In normal mode: The target's NIC ignores the packet (wrong MAC)
- In promiscuous mode: The NIC captures the packet, the OS processes it,
  and sends an ICMP Echo Reply

```
for each attempt:
    1. Build ICMP Echo Request with fake destination MAC (e.g., ff:00:00:00:00:00)
    2. Send packet to target IP
    3. Listen for ICMP Echo Reply
       → Reply received: Target is likely in promiscuous mode
       → No reply: Target is probably not in promiscuous mode (inconclusive)
```

### ARP Test

Similar concept to the ICMP test, but using the ARP protocol. Send an ARP
request with a bogus MAC address and observe whether the target responds.

### DNS Test

Exploit the fact that many sniffers perform reverse DNS lookups on captured
IP addresses (to show hostnames instead of IPs in their output).

```
for each attempt:
    1. Inject fake traffic between two non-existent IP addresses
    2. Monitor the network for DNS PTR (reverse lookup) queries for those IPs
       → Query detected: The source of the query is likely running a sniffer
       → No query: Inconclusive
```

This test detects the *sniffer software's behavior*, not just promiscuous mode.

### Latency Test

Flood the network with packets that only promiscuous-mode interfaces would
process. Measure the target's response time before and during the flood.

```
1. Measure baseline response time (ping RTT)
2. Start flooding with packets addressed to bogus MACs
3. Measure response time during flood
4. Compare:
   → Significant increase: Target is likely processing all packets (promiscuous)
   → No change: Target is ignoring the flood (normal mode)
```

> **Caveat:** This test is highly subjective. Results depend on CPU power,
> network conditions, OS implementation, and flood effectiveness. Use as
> supplementary evidence, not definitive proof.

### Honeypot Test (Not Implemented)

Plant bait traffic containing fake credentials. If someone uses those
credentials, you've found your sniffer operator.

```
1. Inject traffic containing fake passwords (e.g., fake FTP login)
2. Monitor for use of those credentials on your servers
   → Credentials used: Someone captured and used them
```

This doesn't detect the sniffer directly, but catches the attacker using it.

## Limitations

- **False positives:** Some legitimate software uses promiscuous mode
  (network monitors, IDS, virtual machine bridges)
- **False negatives:** Sophisticated sniffers can detect and evade these tests
- **Switched networks:** Limits visibility without additional attack vectors
- **Encrypted traffic:** Modern TLS usage reduces the value of sniffing

## Further Reading

- Comer, Douglas E. *Internetworking with TCP/IP Vol.1: Principles, Protocols,
  and Architecture*. A foundational text on TCP/IP networking.

- The original academic paper (in Portuguese): "Implementação de um Sistema
  Para a Detecção Remota de Sniffers em Redes TCP/IP" covers these techniques
  in greater depth.
