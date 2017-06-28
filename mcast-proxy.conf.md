MCAST-PROXY.CONF(5) - File Formats Manual

# NAME

**mcast-proxy.conf** - Multicast Proxy configuration file

# DESCRIPTION

The
mcast-proxy(8)
daemon implements IGMP/MLD proxy for multicast routing.

# SECTIONS

The
**mcast-proxy.conf**
config file is divided into three main sections.

**Macros**

> User-defined variables may be defined and used later, simplifying the
> configuration file.

**Global Configuration**

> Global settings for
> mcast-proxy(8).
> Allows the configuration of globally supported Internet Protocols
> versions: IPv4 and/or IPv6.

**Interfaces Configuration**

> Interface-specific parameters.

Argument names not beginning with a letter, digit, or underscore
must be quoted.

Additional configuration files can be included with the
**include**
keyword, for example:

	include "/etc/mcast-proxy.sub.conf"

# MACROS

Macros can be defined that will later be expanded in context.
Macro names must start with a letter, digit, or underscore,
and may contain any of those characters.
Macro names may not be reserved words (for example,
**upstreamif**,
**interface**,
or
**default-threshold**).
Macros are not expanded inside quotes.

For example:

	upstreamif="em0"
	default_threshold="1"
	interface $upstreamif {
		threshold $default_threshold
		upstream
	}

# GLOBAL CONFIGURATION

Here are the settings that can be set globally:

**ipv4** (**yes**|**no**)

> Determines if the mcast-proxy will be enabled for IPv4.
> This setting is enabled by default.

**ipv6** (**yes**|**no**)

> Determines if MLD-proxy will be enabled for IPv6.
> This setting is disabled by default.

# INTERFACES CONFIGURATION

This section will describe the interface multicast configuration
options.
An interface is specified by its name.

	interface em0 {
		...
	}

Interface-specific parameters are listed below.

**ipv4** (**yes**|**no**)

> Enables or disables IPv4 support in this interface.
> The default value is inherited from the global configuration.

**ipv6** (**yes**|**no**)

> Enables or disables IPv6 support in this interface.
> The default value is inherited from the global configuration.

**threshold** *number*

> Specify the minimum TTL required in the incoming packets to be
> forwarded (IPv4 only). The default value is 1.

**source** *network*/*prefix*

> Specify an alternate network to receive multicast from.
> By default only multicast traffic coming from the same network of the
> interface will be allowed.

(**disabled**|**downstream**|**upstream**)

> Configure the interface role in the multicast proxying setup.
> *disabled*
> will disable the interface participation,
> *downstream*
> mark client facing interfaces and
> *upstream*
> mark the interface which will receive the multicast traffic.

> By default all interfaces are
> *disabled*.

# FILES

*/etc/mcast-proxy.conf*

> mcast-proxy(8)
> configuration file

# SEE ALSO

mcast-proxy(8),
rc.conf.local(8)

# HISTORY

The
**mcast-proxy.conf**
file format first appeared in
OpenBSD 6.2.

# AUTHORS

The
mcast-proxy(8)
program was written by
Rafael Zalamena &lt;[rzalamena@openbsd.org](mailto:rzalamena@openbsd.org)&gt;.

OpenBSD 6.1 - June 28, 2017
