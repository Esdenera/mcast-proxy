MCAST-PROXY(8) - System Manager's Manual

# NAME

**mcast-proxy** - Multicast Proxy

# SYNOPSIS

**mcast-proxy**
\[**-dnv**]
\[**-D**&nbsp;*macro*=*value*]
\[**-f**&nbsp;*file*]

# DESCRIPTION

**mcast-proxy**
is a multicast proxy implementation for the Internet Group Management
Protocol (IGMP) and Multicast Listener Discovery (MLD) protocols.
It is used on networks that face the client to control the multicast
traffic based on the interest of the local network and to reduce the
load by filtering unneeded multicast traffic.

The options are as follows:

**-D** *macro*=*value*

> Define
> *macro*
> to be set to
> *value*
> on the command line.
> Overrides the definition of
> *macro*
> in the configuration file.

**-d**

> Do not daemonize.
> If this option is specified,
> **mcast-proxy**
> will run in the foreground and log to
> *stderr*.

**-f** *file*

> Specify an alternative configuration file.

**-n**

> Only check the configuration file for validity.

**-v**

> Produce more verbose output.

# FILES

*/etc/mcast-proxy.conf*

> Default
> **mcast-proxy**
> configuration file.

# SEE ALSO

multicast(4),
mcast-proxy.conf(5)

# STANDARDS

S. Deering,
*Host Extensions for IP Multicasting*,
RFC 1112,
August 1989.

W. Fenner,
*Internet Group Management Protocol, Version 2*,
RFC 2236,
November 1997.

M. Christensen,
Thrane & Thrane, and
K. Kimball, and
F. Solensky,
*Considerations for Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Snooping Switches*,
RFC 4541,
May 2006.

B. Fenner,
H. He, and
B. Haberman, and
H. Sandick,
*Internet Group Management Protocol (IGMP) / Multicast Listener Discovery (MLD)-Based Multicast Forwarding ("IGMP/MLD Proxying")*,
RFC 4605,
August 2006.

# HISTORY

The
**mcast-proxy**
program first appeared in
OpenBSD 6.2.

# AUTHORS

**mcast-proxy**
was written by
Rafael Zalamena &lt;[rzalamena@openbsd.org](mailto:rzalamena@openbsd.org)&gt;

OpenBSD 6.1 - June 28, 2017
