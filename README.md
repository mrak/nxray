# nxray

| Pronunciation: NIC-X-Ray/NICsRay/N-X/Nick's Ray/En Ex/_Nickus Ex Reikimus_

`nx` reads packet (or frame) information traversing your network interfaces.
Similar to the venerable `tcpdump`, it can additionally filter packet
information based on L2 to L4[¹](https://en.wikipedia.org/wiki/OSI_model) criteria using a simplified CLI argument syntax.

## Examples

Notice that any example command preceded by `#` denotes root or privileged
access to the system. Anywhere `MY.LOCAL.IP.ADDr` is present is replaced with your actual
machine IP address.

### Show all TCP or UDP packets

```console
# nx
```

### Show any standard DNS request

```console
#nx :53
```

### Show all DNS requests to CloudFlare

```console
# nx 1.{1.1,0.0}.1:53
```

### Show ICMP packets to/from any interface

```console
# nx icmp
```

### Show any packets to/from private domains

```console
# nx 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8
```

### Show all packets between my machine and router

Assuming local network is `192.168.1.0/24`:

```console
# nx MY.LOCAL.IP.ADDR=192.168.1.1
```

### Show only packets targeting specific IP:port

```console
# nx @10.1.2.3:1234
```

### Show only packets originating from specific IP

```console
# nx ^10.1.2.3
```

# Development TODO

- [ ] pcap format
- [ ] colorized output
- [ ] man(1) page
- [ ] ethernet-frame-only filtering
