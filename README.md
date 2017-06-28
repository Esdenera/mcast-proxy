mcast-proxy
===========

About
-----

This is a new daemon for OpenBSD that fills in a gap in the multicast
protocol support for network edges. More specifically we're talking
about a multicast proxy.

The mcast-proxy is a less featured multicast routing daemon that is
mostly used on equipments that face client networks (end users). It is
mainly used when you don't need a full multicast routing daemon (like
dvmrpd, mrouted or pim), but you want to use your networks resources
efficiently. This implementation has the following features:

* Support IPv4 (IGMPv1/v2) multicast proxy
* Support IPv6 (MLDv1) multicast proxy
* Privilege dropping (runs as user)
* chroot jailing

The development of this daemon brought improvements to the IPv6
multicast stack, like:

* Initial MP support
  Now IPv6 multicast routing code uses the art routing table to store
  the multicast routes. This also means you can see your multicast
  routes in route(8).
* Support multiple rdomains
  The interfaces mif (multicast interface) are now domain specific, so
  you can have mif ids duplicated on different rdomains.
* Fixed a few problems in MLD code that prevented some client/server
  functionality

Notes
-----

* The daemon is not yet pledge()d as there is no support for
  MRT(6)_* setsockopt() calls.
* IPv6 multicast proxy requires an OpenBSD -current, because of
  the recent kernel changes and netstat(8).

Running mcast-proxy
-------------------

To run multicast routing protocols in your machines you have to configure
the following settings:

* Allow multicast routing:

        rcctl enable multicast

* (IPv4 only) allow IGMP packets.
  To allow IP options you have to configure your PF traffic pass rule to
  accept IP options. Example: change 'pass' to 'pass allow-opts'.

* Add a multicast route (if the default doesn't exist or is not correct)

        route add 224/8 192.168.0.1
        route add ff00::/8 fe80::fce1:baff:fed0:2001%vio1

* In case you are using the default route for multicast you might need
  to specify an alternate multicast source. By default mcast-proxy only
  accepts multicast traffic from the same network of your interface.
  For example em0 has IPv6 address: 2001:db8::100,
  but the multicast traffic comes from 2001:db9::10. The same applies for IPv4.
  The `mcast-proxy.conf`:

        interface em0 {
        	source 2001:db9::/64
        	upstream
        }

Design
------

The daemon code is split in the following file hierarchy:

* mcast-proxy.c: all IGMP/MLD related packet parsing
* mrt.c: the multicast routing table on userland
* kroute.c: all kernel interactions
* util.c: misc functions that did not fit the other files

Further Reading
---------------

* [mcast-proxy.8](mcast-proxy.md)
* [mcast-proxy.conf.5](mcast-proxy.conf.md)
* [License][LICENSE.md]
