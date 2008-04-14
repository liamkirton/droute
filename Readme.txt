================================================================================
Droute 0.1.1
Copyright ©2007 Liam Kirton <liam@int3.ws>

12th August 2007
http://int3.ws/
================================================================================

This is a slightly crazy tool, for which there possibly exists no conceivable
purpose, other than the amusement/knowledge that was gained in coding it.

Droute creates two virtual network interfaces, existing on one or more Winpcap
devices, and routes traffic between them (with or without NAT).

For instance, consider an adapter that is plugged into a physical network
carrying two LANS: 192.168.0.0/24 and 10.0.0.0/16. Droute will allow you to
establish a virtual interface upon each LAN, and then route traffic between the
two.

Droute.exe /Nat 5;;10.0.0.254;255.255.0.0 5;192.168.0.254;255.255.255.0;

This creates interfaces 10.0.0.254 and 192.168.0.254 (both on Winpcap device 5),
and performs NAT routing for packets leaving 192.168.0.0/24 via 192.168.0.254,
bound for 10.0.0.0/16 (i.e. they’re re-written with source address 10.0.0.254).

So, given an adapter default address of 192.168.0.1, adding a manual route
like so:

route.exe add 10.0.0.0 mask 255.255.0.0 192.168.0.254

will allow you (or anyone on the 192.168.0.0/24 LAN with such a route 
configured) to send traffic to 10.0.0.0/16. Obviously, if a corresponding
reverse route to 192.168.0.0/24 is established, then there is no need for NAT.

As a bonus feature, one can specify the MAC address for each virtual adapter
as the second parameter within an interface definition string.

Format: Device;MAC;IP;Netmask;Gateway

Example: 5;00:01:02:03:04:05;192.168.0.254;255.255.255.0;192.168.0.1

This will probably allow for device spoofing of some sort.

Note: ICMP packets are currently routed, but will not undergo NAT.

================================================================================