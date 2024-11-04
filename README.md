# Simple network sniffer (Only for linux)

A Network Packet Sniffer developed in C.\
**P.S The utility is under development**

## How to use
```
git clone https://github.com/leavemealonemf/simple-network-sniffer.git
cd simply-sniffer
make
./sniffer.out <network interface> <packet's count>

For example (./sniffer.out eth0 1)
```
**Result**

```
-----------------------
 - Destination MAC Addr: 4C D0 E3 A5 C1 11 
 - Source MAC Addr: 7A C3 A4 A2 71 19 
 - Protocol: 08 00 
 - Destination IP Addr: 192.168.0.100
 - Source IP Addr: 64.31.100.58
----------------------- 
 - Destination MAC Addr: 4C D0 E3 A5 C1 11 
 - Source MAC Addr: 7A C3 A4 A2 71 19 
 - Protocol: 08 00 
 - Destination IP Addr: 192.168.0.100
 - Source IP Addr: 64.31.100.58
```
## Others
> **TODO:** TCP header parse & data parse
