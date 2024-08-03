# nxray

| Pronunciation: NIC-X-Ray/NICsRay/N-X/Nick's Ray/En Ex/_Nickus Ex Reikimus_

`nx` reads packet (or frame) information traversing your network interfaces.
Similar to the venerable `tcpdump`, it can additionally filter packet
information based on L2 to L4[¹](https://en.wikipedia.org/wiki/OSI_model) criteria using a simplified CLI argument syntax.

> [!IMPORTANT]
> Works with **Linux** and **MacOS**. Windows is not currently supported.

## Examples

Notice that any example command preceded by `#` denotes root or privileged
access to the system. Anywhere `MY.LOCAL.IP.ADDR` is present is replaced with your actual
machine IP address.

### Show all TCP and UDP packets

```console
# nx
```

### Show all TCP and UDP packets from a given interface

```console
# nx eth0
```

### Show only ARP and ICMP packets

```console
# nx arp icmp
```

### Show any standard DNS request

```console
# nx :53
```

### Show all DNS requests to CloudFlare

```console
# nx 1.{1.1,0.0}.1:53 [2606:4700:4700::1{11,00}1]:53
```

### Show any packets to/from private domains

```console
# nx 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8
```

### Show any private network SSH packets

```console
# nx 192.168.0.0/16:22 172.16.0.0/12:22 10.0.0.0/8:22
```

### Show packets to/from MAC address

```console
# nx aa:bb:cc:dd:ee:ff
```

### Show only packets targeting specific IP:port

The `@` anchor matches the destination fields of packets.

```console
# nx @10.1.2.3:1234
```

### Show only packets originating from specific IP

The `^` anchor matches the source fields of packets.

```console
# nx ^10.1.2.3
```

### Show only packets originating from specific IP and targeting a specific IP

`@` and `^` can be used together to match packets matching both their source AND
destination

```console
# nx ^10.1.2.3@10.4.5.6
```

The following, for instance, matches any packets originating from `10.1.2.3` OR
packets targeting `10.4.5.6`.

```console
# nx ^10.1.2.3 @10.4.5.6
```

### Show all packets to/from my machine and router

The `=` infix operator matches packets where the left/right side are the
src/destination fields OR the destination/src fields.

Assuming local network is `192.168.1.0/24`:

```console
# nx MY.LOCAL.IP.ADDR=192.168.1.1
```

This is equivalent to the following:

```console
# nx ^MY.LOCAL.IP.ADDR@192.168.1.1 @MY.LOCAL.IP.ADDR^192.168.1.1
```


# Development TODO

- [x] tcp
- [x] udp
- [x] icmp
- [x] icmpv6
- [x] arp
- [x] ip-in-ip
- [x] MAC filters
- [x] IP filters
- [x] port filters
- [x] TCP/UDP filters
- [x] CIDR filters
- [x] ICMP specialized output
- [x] colorized output
- [x] ~~Geneve (UDP port 6081, basically)~~ (Wont do)
- [ ] man(1) page
- [ ] MPLS (EtherType)
- [ ] VLAN (EtherType)
- [ ] VXLAN (EtherType)
- [ ] GRE (IP 47 or UDP)
- [ ] pcap format
