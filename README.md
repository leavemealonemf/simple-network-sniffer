# Simple network sniffer (Only for linux)

A Network Packet Sniffer developed in C.

## How to use
```
git clone https://github.com/leavemealonemf/simple-network-sniffer.git
cd simple-network-sniffer
make
sudo ./simple-network-sniffer.out <network interface> <packet's count>

For example (./simple-network-sniffer.out eth0 2)
```
**Result**

```
 - Destination MAC Addr: 82:93:9f:3d:a9:3e
 - Source MAC Addr: 8a:82:d3:02:45:49
 - Protocol: IPv4
 - Destination IP Addr: 192.168.0.101
 - Source IP Addr: 223.122.122.12
 - Destination PORT: 52310
 - Source PORT: 65411
 - Data Length: 20
 - Data: 0A 04 05 82 04 02 08 0A 77 11 14 5D 72 6E 62 4D 01 03 03 01 
----------------------------------
 - Destination MAC Addr: 82:93:9f:3d:a9:3e
 - Source MAC Addr: 8a:82:d3:02:45:49
 - Protocol: IPv4
 - Destination IP Addr: 192.168.0.102
 - Source IP Addr: 12.111.226.33
 - Destination PORT: 52310
 - Source PORT: 443
 - Data Length: 20
 - Data: 0A 04 05 82 04 02 08 0A 77 11 14 5D 72 6E 62 4D 01 03 03 01 
```
