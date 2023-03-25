/*	$OpenBSD:$	*/

/*
 * Copyright (c) 2017 Rafael Zalamena <rzalamena@openbsd.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>

#include "mcast-proxy.h"

const char *
addrtostr(struct sockaddr_storage *ss)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	static char		 buf[4][128];
	static unsigned int	 bufpos = 0;

	bufpos = (bufpos + 1) % 4;

	switch (ss->ss_family) {
	case AF_INET:
		sin = sstosin(ss);
		inet_ntop(AF_INET, &sin->sin_addr, buf[bufpos],
		    sizeof(buf[bufpos]));
		return buf[bufpos];
	case AF_INET6:
		sin6 = sstosin6(ss);
		buf[bufpos][0] = '[';
		inet_ntop(AF_INET6, &sin6->sin6_addr, &buf[bufpos][1],
		    sizeof(buf[bufpos]));
		strlcat(buf[bufpos], "]", sizeof(buf[bufpos]));
		return buf[bufpos];

	default:
		return "unknown";
	}
}

const char *
addr4tostr(struct in_addr *addr)
{
	struct sockaddr_storage		 ss;

	memset(&ss, 0, sizeof(ss));
	ss.ss_family = AF_INET;
	ss.ss_len = sizeof(struct sockaddr_in);
	sstosin(&ss)->sin_addr = *addr;

	return addrtostr(&ss);
}

const char *
addr6tostr(struct in6_addr *addr)
{
	struct sockaddr_storage		 ss;

	memset(&ss, 0, sizeof(ss));
	ss.ss_family = AF_INET6;
	ss.ss_len = sizeof(struct sockaddr_in6);
	memcpy(&sstosin6(&ss)->sin6_addr, addr, sizeof(*addr));

	return addrtostr(&ss);
}

int
id_matchaddr4(struct intf_data *id, uint32_t addr)
{
	struct intf_addr	*ia;
	union uaddr		 addrorg, addrtgt, naddr;

	naddr.v4.s_addr = addr;

	/* Check for address in interface address list. */
	SLIST_FOREACH(ia, &id->id_ialist, ia_entry) {
		if (ia->ia_af != AF_INET)
			continue;

		applymask(AF_INET, &addrtgt, &naddr, ia->ia_prefixlen);
		applymask(AF_INET, &addrorg, &ia->ia_addr, ia->ia_prefixlen);
		if (memcmp(&addrorg, &addrtgt, sizeof(addrorg.v4)) == 0)
			return 1;
	}

	/* Check for address in the subnet address list. */
	SLIST_FOREACH(ia, &id->id_altnetlist, ia_entry) {
		if (ia->ia_af != AF_INET)
			continue;

		applymask(AF_INET, &addrtgt, &naddr, ia->ia_prefixlen);
		applymask(AF_INET, &addrorg, &ia->ia_addr, ia->ia_prefixlen);
		if (memcmp(&addrorg, &addrtgt, sizeof(addrorg.v4)) == 0)
			return 1;
	}

	return 0;
}

int
id_matchaddr6(struct intf_data *id, struct in6_addr *addr)
{
	struct intf_addr	*ia;
	union uaddr		 addrorg, addrtgt, naddr;

	naddr.v6 = *addr;

	/* Check for address in interface address list. */
	SLIST_FOREACH(ia, &id->id_ialist, ia_entry) {
		if (ia->ia_af != AF_INET6)
			continue;

		applymask(AF_INET6, &addrtgt, &naddr, ia->ia_prefixlen);
		applymask(AF_INET6, &addrorg, &ia->ia_addr, ia->ia_prefixlen);
		if (memcmp(&addrorg, &addrtgt, sizeof(addrorg.v6)) == 0)
			return 1;
	}

	/* Check for address in the subnet address list. */
	SLIST_FOREACH(ia, &id->id_altnetlist, ia_entry) {
		if (ia->ia_af != AF_INET6)
			continue;

		applymask(AF_INET6, &addrtgt, &naddr, ia->ia_prefixlen);
		applymask(AF_INET6, &addrorg, &ia->ia_addr, ia->ia_prefixlen);
		if (memcmp(&addrorg, &addrtgt, sizeof(addrorg.v6)) == 0)
			return 1;
	}

	return 0;
}

struct intf_data *
intf_lookupbyname(const char *ifname)
{
	struct intf_data	*id;

	SLIST_FOREACH(id, &iflist, id_entry) {
		if (strcmp(id->id_name, ifname) == 0)
			return id;
	}

	return NULL;
}

struct intf_data *
intf_lookupbyindex(unsigned short index)
{
	struct intf_data	*id;

	SLIST_FOREACH(id, &iflist, id_entry) {
		if (id->id_index == index)
			return id;
	}

	return NULL;
}

struct intf_data *
intf_lookupbyaddr4(uint32_t addr)
{
	struct intf_data	*id;

	SLIST_FOREACH(id, &iflist, id_entry) {
		if (id_matchaddr4(id, addr))
			return id;
	}

	return NULL;
}

struct intf_data *
intf_lookupbyaddr6(struct in6_addr *addr)
{
	struct intf_data	*id;

	SLIST_FOREACH(id, &iflist, id_entry) {
		if (id_matchaddr6(id, addr))
			return id;
	}

	return NULL;
}

struct intf_addr *
intf_primaryv4(struct intf_data *id)
{
	struct intf_addr	*ia;

	SLIST_FOREACH(ia, &id->id_ialist, ia_entry) {
		if (ia->ia_af != AF_INET)
			continue;

		return ia;
	}

	return NULL;
}

struct intf_addr *
intf_ipv6linklayer(struct intf_data *id)
{
	struct intf_addr	*ia;

	SLIST_FOREACH(ia, &id->id_ialist, ia_entry) {
		if (ia->ia_af != AF_INET6)
			continue;
		if (!IN6_IS_ADDR_LINKLOCAL(&ia->ia_addr.v6))
			continue;

		return ia;
	}

	return NULL;
}

void
ia_inserttail(struct ialist *ial, struct intf_addr *ia)
{
	struct intf_addr	*ian;

	SLIST_FOREACH(ian, ial, ia_entry) {
		if (SLIST_NEXT(ian, ia_entry) == NULL)
			break;
	}
	if (ian != NULL)
		SLIST_INSERT_AFTER(ian, ia, ia_entry);
	else
		SLIST_INSERT_HEAD(ial, ia, ia_entry);
}

struct intf_data *
id_new(void)
{
	struct intf_data	*id;

	id = calloc(1, sizeof(*id));
	if (id == NULL) {
		log_warn("%s: calloc", __func__);
		return NULL;
	}

	/* Default minimum TTL threshold. */
	id->id_ttl = 1;

	id->id_index = (unsigned short)-1;
	id->id_vindex = INVALID_VINDEX;
	id->id_vindex6 = INVALID_VINDEX;
	SLIST_INSERT_HEAD(&iflist, id, id_entry);

	return id;
}

struct intf_data *
id_insert(unsigned short index)
{
	struct intf_data	*id;

	id = intf_lookupbyindex(index);
	if (id != NULL)
		return id;

	id = id_new();
	if (id == NULL)
		return NULL;

	id->id_index = index;

	return id;
}

void
id_free(struct intf_data *id)
{
	struct intf_addr	*ia;

	if (id == NULL)
		return;

	while (!SLIST_EMPTY(&id->id_ialist)) {
		ia = SLIST_FIRST(&id->id_ialist);
		SLIST_REMOVE(&id->id_ialist, ia, intf_addr, ia_entry);
		free(ia);
	}
	while (!SLIST_EMPTY(&id->id_altnetlist)) {
		ia = SLIST_FIRST(&id->id_altnetlist);
		SLIST_REMOVE(&id->id_altnetlist, ia, intf_addr, ia_entry);
		free(ia);
	}

	SLIST_REMOVE(&iflist, id, intf_data, id_entry);
	free(id);
}

uint8_t
mask2prefixlen(in_addr_t ina)
{
	if (ina == 0)
		return (0);
	else
		return (33 - ffs(ntohl(ina)));
}

uint8_t
mask2prefixlen6(struct sockaddr_in6 *sa_in6)
{
	uint8_t	l = 0, *ap, *ep;

	/*
	 * sin6_len is the size of the sockaddr so subtract the offset of
	 * the possibly truncated sin6_addr struct.
	 */
	ap = (uint8_t *)&sa_in6->sin6_addr;
	ep = (uint8_t *)sa_in6 + sa_in6->sin6_len;
	for (; ap < ep; ap++) {
		/* this "beauty" is adopted from sbin/route/show.c ... */
		switch (*ap) {
		case 0xff:
			l += 8;
			break;
		case 0xfe:
			l += 7;
			return (l);
		case 0xfc:
			l += 6;
			return (l);
		case 0xf8:
			l += 5;
			return (l);
		case 0xf0:
			l += 4;
			return (l);
		case 0xe0:
			l += 3;
			return (l);
		case 0xc0:
			l += 2;
			return (l);
		case 0x80:
			l += 1;
			return (l);
		case 0x00:
			return (l);
		default:
			fatalx("%s: non contiguous inet6 netmask", __func__);
		}
	}

	return (l);
}

in_addr_t
prefixlen2mask(uint8_t prefixlen)
{
	if (prefixlen == 0)
		return (0);

	return (htonl(0xffffffff << (32 - prefixlen)));
}

void
applymask(int af, union uaddr *dest, const union uaddr *src,
    int prefixlen)
{
	struct in6_addr	mask;
	int		i;

	switch (af) {
	case AF_INET:
		dest->v4.s_addr = src->v4.s_addr & prefixlen2mask(prefixlen);
		break;
	case AF_INET6:
		memset(&mask, 0, sizeof(mask));
		for (i = 0; i < prefixlen / 8; i++)
			mask.s6_addr[i] = 0xff;
		i = prefixlen % 8;
		if (i)
			mask.s6_addr[prefixlen / 8] = 0xff00 >> i;

		for (i = 0; i < 16; i++)
			dest->v6.s6_addr[i] = src->v6.s6_addr[i] &
			    mask.s6_addr[i];
		break;
	default:
		fatalx("%s: unknown address family", __func__);
	}
}

/* Packet assembly code, originally contributed by Archie Cobbs. */

/*
 * Copyright (c) 1995, 1996, 1999 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

uint16_t
checksum(uint8_t *buf, uint16_t nbytes, uint32_t sum)
{
	unsigned int i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (nbytes & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(buf + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < nbytes) {
		sum += buf[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return sum;
}

uint16_t
wrapsum(uint16_t sum)
{
	sum = ~sum & 0xFFFF;
	return htons(sum);
}
