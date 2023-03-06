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

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip_mroute.h>
#include <netinet6/ip6_mroute.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mcast-proxy.h"

#define MAX_RTSOCK_BUF	(128 * 1024)

int bad_addr_v4(struct in_addr);
int bad_addr_v6(struct in6_addr *);
int iacmp(struct intf_addr *, struct intf_addr *);

int vif4_nextvidx(void);
int vif6_nextvidx(void);

void if_announce(struct if_announcemsghdr *);
void if_update(unsigned short, int, struct if_data *,
    struct sockaddr_dl *sdl);
void if_newaddr(unsigned short, struct sockaddr *, struct sockaddr *);
void if_deladdr(unsigned short, struct sockaddr *, struct sockaddr *);
void get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
void rtmsg_process(const uint8_t *, size_t);

struct in6_addr in6_allrouters = IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;

int vindex;
int vindex6;
int rtsd_rcvbuf;

void
assert_mcastforward(void)
{
	int		 mforward = 0;
	size_t		 mforwardlen = sizeof(mforward);
	int		 mib[4];

	if (!ic.ic_ipv4)
		goto skip_v4mforwarding;

	mib[0] = CTL_NET;
	mib[1] = PF_INET;
	mib[2] = IPPROTO_IP;
	mib[3] = IPCTL_MFORWARDING;
	if (sysctl(mib, nitems(mib), &mforward, &mforwardlen, NULL, 0) == -1)
		fatal("sysctl IPv4 IPCTL_MFORWARDING");

	if (!mforward)
		fatalx("%s: IPv4 multicast forwarding is disabled",
		    __func__);

 skip_v4mforwarding:
	if (!ic.ic_ipv6)
		return;

	mib[0] = CTL_NET;
	mib[1] = PF_INET6;
	mib[2] = IPPROTO_IPV6;
	mib[3] = IPV6CTL_MFORWARDING;
	if (sysctl(mib, nitems(mib), &mforward, &mforwardlen, NULL, 0) == -1)
		fatal("sysctl IPv6 IPCTL_MFORWARDING");

	if (!mforward)
		fatalx("%s: IPv6 multicast forwarding is disabled",
		    __func__);
}

int
open_igmp_socket(void)
{
	int		 sd, v;
	uint8_t		 ttl = 1, loop = 0;

	sd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_IGMP);
	if (sd == -1) {
		log_warn("%s: socket", __func__);
		return -1;
	}

	/* Initialize the multicast routing socket. */
	v = 1;
	if (setsockopt(sd, IPPROTO_IP, MRT_INIT, &v, sizeof(v)) == -1) {
		log_warn("%s: setsockopt MRT_INIT", __func__);
		close(sd);
		return -1;
	}

	/* Include IP header on packets. */
	v = 1;
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &v, sizeof(v)) == -1) {
		log_warn("%s: setsockopt IP_HDRINCL", __func__);
		close(sd);
		return -1;
	}

	/* Use TTL of 1 to send multicast packets. */
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
	    sizeof(ttl)) == -1) {
		log_warn("%s: setsockopt IP_MULTICAST_TTL", __func__);
		close(sd);
		return -1;
	}

	/* Don't send multicast packets to loopback. */
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
	    sizeof(loop)) == -1) {
		log_warn("%s: setsockopt IP_MULTICAST_LOOP", __func__);
		close(sd);
		return -1;
	}

	return sd;
}

int
close_igmp_socket(int sd)
{
	if (sd == -1)
		return 0;

	if (setsockopt(sd, IPPROTO_IP, MRT_DONE, NULL, 0) == -1) {
		log_warn("%s: setsockopt MRT_DONE", __func__);
		return -1;
	}

	if (close(sd) == -1) {
		log_warn("%s: close", __func__);
		return -1;
	}

	return 0;
}

int
open_mld_socket(void)
{
	int		 sd, v;
	unsigned int	 ttl = 1;

	sd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sd == -1) {
		log_warn("%s: socket", __func__);
		return -1;
	}

	/* Initialize the multicast routing socket. */
	v = 1;
	if (setsockopt(sd, IPPROTO_IPV6, MRT6_INIT, &v, sizeof(v)) == -1) {
		log_warn("%s: setsockopt MRT6_INIT", __func__);
		close(sd);
		return -1;
	}

	/* Include IP header on packets. */
	v = 1;
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &v,
	    sizeof(v)) == -1) {
		log_warn("%s: setsockopt IPV6_RECVPKTINFO", __func__);
		close(sd);
		return -1;
	}

	/* Use TTL of 1 to send multicast packets. */
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl,
	    sizeof(ttl)) == -1) {
		log_warn("%s: setsockopt IPV6_MULTICAST_HOPS", __func__);
		close(sd);
		return -1;
	}

	return sd;
}

int
close_mld_socket(int sd)
{
	if (sd == -1)
		return 0;

	if (setsockopt(sd, IPPROTO_IPV6, MRT6_DONE, NULL, 0) == -1) {
		log_warn("%s: setsockopt MRT6_DONE", __func__);
		return -1;
	}

	if (close(sd) == -1) {
		log_warn("%s: close", __func__);
		return -1;
	}

	return 0;
}

int
igmp_setif(struct intf_data *id)
{
	struct intf_addr	*ia;
	struct in_addr		 any;

	if (id == NULL) {
		memset(&any, 0, sizeof(any));
		if (setsockopt(igmpsd, IPPROTO_IP, IP_MULTICAST_IF,
		    &any, sizeof(any)) == -1) {
			log_warn("%s: setsockopt IP_MULTICAST_IF default",
			    __func__);
			return -1;
		}
		return 0;
	}

	ia = intf_primaryv4(id);
	if (ia == NULL)
		return -1;

	if (setsockopt(igmpsd, IPPROTO_IP, IP_MULTICAST_IF,
	    &ia->ia_addr.v4, sizeof(ia->ia_addr.v4)) == -1) {
		log_warn("%s: setsockopt IP_MULTICAST_IF %s",
		    __func__, id->id_name);
		return -1;
	}

	return 0;
}

int
vif_register(struct intf_data *id)
{
	int	error = 0;

	if (id->id_vindex == INVALID_VINDEX)
		error |= vif4_register(id);
	if (id->id_vindex6 == INVALID_VINDEX)
		error |= vif6_register(id);

	return error;
}

int
vif_unregister(struct intf_data *id)
{
	int	error = 0;

	if (id->id_vindex != INVALID_VINDEX)
		error |= vif4_unregister(id);
	if (id->id_vindex != INVALID_VINDEX)
		error |= vif6_unregister(id);

	return error;
}

int
vif4_nextvidx(void)
{
	struct intf_data	*id;
	int			 vidx;

	for (vidx = 0; vidx < MAXMIFS; vidx++) {
		SLIST_FOREACH(id, &iflist, id_entry) {
			if (vidx == id->id_vindex)
				break;
		}
		if (id != NULL)
			continue;

		return vidx;
	}

	return -1;
}

int
vif4_register(struct intf_data *id)
{
	struct intf_addr	*ia;
	struct vifctl		 vifc;
	int			 vidx;

	/* Don't allow registration if not selected. */
	if (!id->id_mv4)
		return 0;

	/* Already registered. */
	if (id->id_vindex != INVALID_VINDEX)
		return 0;

	ia = intf_primaryv4(id);
	if (ia == NULL)
		return -1;

	memset(&vifc, 0, sizeof(vifc));
	vifc.vifc_flags = 0;
	vifc.vifc_threshold = id->id_ttl;
	vifc.vifc_rate_limit = 0;
	vifc.vifc_lcl_addr = ia->ia_addr.v4;
	vifc.vifc_rmt_addr.s_addr = INADDR_ANY;

	vidx = vif4_nextvidx();
	if (vidx == -1) {
		log_warnx("%s: no more virtual interfaces available",
		    __func__);
		return -1;
	}

	vifc.vifc_vifi = id->id_vindex = vidx;
	log_debug("%s: %s (vindex %d) threshold %d rate %d address %s",
	    __func__, id->id_name, id->id_vindex, id->id_ttl, 0,
	    addr4tostr(&ia->ia_addr.v4));

	if (setsockopt(igmpsd, IPPROTO_IP, MRT_ADD_VIF, &vifc,
	    sizeof(vifc)) == -1) {
		id->id_vindex = INVALID_VINDEX;
		log_warn("%s: setsockopt MRT_ADD_VIF", __func__);
		return -1;
	}

	return 0;
}

int
vif4_unregister(struct intf_data *id)
{
	struct intf_addr	*ia;
	struct vifctl		 vifc;

	/* Don't allow registration if not selected. */
	if (!id->id_mv4)
		return 0;

	/* Already unregistered. */
	if (id->id_vindex == INVALID_VINDEX)
		return 0;

	ia = intf_primaryv4(id);
	if (ia == NULL)
		return -1;

	memset(&vifc, 0, sizeof(vifc));
	vifc.vifc_flags = 0;
	vifc.vifc_vifi = id->id_vindex;
	vifc.vifc_threshold = id->id_ttl;
	vifc.vifc_rate_limit = 0;
	vifc.vifc_lcl_addr = ia->ia_addr.v4;
	vifc.vifc_rmt_addr.s_addr = INADDR_ANY;

	log_debug("%s: %s (%d) threshold %d rate %d address %s",
	    __func__, id->id_name, id->id_vindex, id->id_ttl, 0,
	    addr4tostr(&ia->ia_addr.v4));

	if (setsockopt(igmpsd, IPPROTO_IP, MRT_DEL_VIF, &vifc,
	    sizeof(vifc)) == -1) {
		log_warn("%s: setsockopt MRT_DEL_VIF", __func__);
		return -1;
	}

	id->id_vindex = INVALID_VINDEX;

	return 0;
}

int
vif6_nextvidx(void)
{
	struct intf_data	*id;
	int			 vidx;

	for (vidx = 0; vidx < MAXMIFS; vidx++) {
		SLIST_FOREACH(id, &iflist, id_entry) {
			if (vidx == id->id_vindex6)
				break;
		}
		if (id != NULL)
			continue;

		return vidx;
	}

	return -1;
}

int
vif6_register(struct intf_data *id)
{
	struct mif6ctl		 mif6c;
	int			 vidx;

	/* Don't allow registration if not selected. */
	if (!id->id_mv6)
		return 0;

	/* Already registered. */
	if (id->id_vindex6 != INVALID_VINDEX)
		return 0;

	memset(&mif6c, 0, sizeof(mif6c));
	mif6c.mif6c_pifi = id->id_index;

	vidx = vif6_nextvidx();
	if (vidx == -1) {
		log_warnx("%s: no more virtual interfaces available",
		    __func__);
		return -1;
	}

	id->id_vindex6 = mif6c.mif6c_mifi = vidx;
	log_debug("%s: %s (vindex %d) rate %d",
	    __func__, id->id_name, id->id_vindex6, 0);

	if (setsockopt(mldsd, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6c,
	    sizeof(mif6c)) == -1) {
		id->id_vindex6 = INVALID_VINDEX;
		log_warn("%s: setsockopt MRT6_ADD_MIF", __func__);
		return -1;
	}

	return 0;
}

int
vif6_unregister(struct intf_data *id)
{
	struct mif6ctl		 mif6c;

	/* Don't allow registration if not selected. */
	if (!id->id_mv6)
		return 0;

	/* Already unregistered. */
	if (id->id_vindex6 == INVALID_VINDEX)
		return 0;

	memset(&mif6c, 0, sizeof(mif6c));
	mif6c.mif6c_pifi = id->id_index;

	log_debug("%s: %s (vindex %d) rate %d",
	    __func__, id->id_name, id->id_vindex6, 0);

	if (setsockopt(mldsd, IPPROTO_IPV6, MRT6_DEL_MIF, &mif6c,
	    sizeof(mif6c)) == -1) {
		log_warn("%s: setsockopt MRT6_DEL_MIF", __func__);
		return -1;
	}

	id->id_vindex6 = INVALID_VINDEX;

	return 0;
}

int
mcast_join(struct intf_data *id, struct sockaddr_storage *ss)
{
	int	error = 0;

	if (ss == NULL) {
		error |= mcast4_join(id, NULL);
		error |= mcast6_join(id, NULL);
	} else {
		switch (ss->ss_family) {
		case AF_INET:
			error = mcast4_join(id, &sstosin(ss)->sin_addr);
			break;
		case AF_INET6:
			error = mcast6_join(id, &sstosin6(ss)->sin6_addr);
			break;

		default:
			log_debug("%s: invalid protocol %d",
			    __func__, ss->ss_family);
			error = -1;
		}
	}

	return error;
}

int
mcast_leave(struct intf_data *id, struct sockaddr_storage *ss)
{
	int	error = 0;

	if (ss == NULL) {
		error |= mcast4_leave(id, NULL);
		error |= mcast6_leave(id, NULL);
	} else {
		switch (ss->ss_family) {
		case AF_INET:
			error = mcast4_leave(id, &sstosin(ss)->sin_addr);
			break;
		case AF_INET6:
			error = mcast6_leave(id, &sstosin6(ss)->sin6_addr);
			break;

		default:
			log_debug("%s: invalid protocol %d",
			    __func__, ss->ss_family);
			error = -1;
		}
	}

	return error;
}

int
mcast4_join(struct intf_data *id, struct in_addr *in)
{
	struct intf_addr	*ia;
	struct ip_mreq		 imr;

	/* IPv4 is disabled in this interface. */
	if (!id->id_mv4)
		return 0;

	ia = intf_primaryv4(id);
	if (ia == NULL)
		return -1;

	if (in == NULL)
		log_debug("%s: %s (%d) address %s group all_routers",
		    __func__, id->id_name, id->id_vindex,
		    addr4tostr(&ia->ia_addr.v4));
	else
		log_debug("%s: %s (%d) address %s group %s",
		    __func__, id->id_name, id->id_vindex,
		    addr4tostr(&ia->ia_addr.v4), addr4tostr(in));

	imr.imr_multiaddr.s_addr = (in == NULL) ?
	    htonl(INADDR_ALLROUTERS_GROUP) : in->s_addr;
	imr.imr_interface = ia->ia_addr.v4;
	if (setsockopt(igmpsd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr,
	    sizeof(imr)) == -1) {
		log_debug("%s: setsockopt IP_ADD_MEMBERSHIP: %s",
		    __func__, strerror(errno));
		return -1;
	}

	return 0;
}

int
mcast4_leave(struct intf_data *id, struct in_addr *in)
{
	struct intf_addr	*ia;
	struct ip_mreq		 imr;

	/* IPv4 is disabled in this interface. */
	if (!id->id_mv4)
		return 0;

	ia = intf_primaryv4(id);
	if (ia == NULL)
		return -1;

	if (in == NULL)
		log_debug("%s: %s (%d) address %s group all_routers",
		    __func__, id->id_name, id->id_vindex,
		    addr4tostr(&ia->ia_addr.v4));
	else
		log_debug("%s: %s (%d) address %s group %s",
		    __func__, id->id_name, id->id_vindex,
		    addr4tostr(&ia->ia_addr.v4), addr4tostr(in));

	imr.imr_multiaddr.s_addr = (in == NULL) ?
	    htonl(INADDR_ALLROUTERS_GROUP) : in->s_addr;
	imr.imr_interface = ia->ia_addr.v4;
	if (setsockopt(igmpsd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &imr,
	    sizeof(imr)) == -1) {
		log_debug("%s: setsockopt IP_DROP_MEMBERSHIP: %s",
		    __func__, strerror(errno));
		return -1;
	}

	return 0;
}

int
mcast6_join(struct intf_data *id, struct in6_addr *in6)
{
	struct ipv6_mreq	 ipv6mr;

	/* IPv6 is disabled in this interface. */
	if (!id->id_mv6)
		return 0;

	if (in6 == NULL)
		log_debug("%s: %s (%d) group all_routers",
		    __func__, id->id_name, id->id_vindex6);
	else
		log_debug("%s: %s (%d) group %s",
		    __func__, id->id_name, id->id_vindex6, addr6tostr(in6));

	ipv6mr.ipv6mr_multiaddr = (in6 == NULL) ? in6_allrouters : *in6;
	ipv6mr.ipv6mr_interface = id->id_index;
	if (setsockopt(mldsd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &ipv6mr,
	    sizeof(ipv6mr)) == -1) {
		log_debug("%s: setsockopt IPV6_JOIN_GROUP: %s",
		    __func__, strerror(errno));
		return -1;
	}

	return 0;
}

int
mcast6_leave(struct intf_data *id, struct in6_addr *in6)
{
	struct ipv6_mreq	 ipv6mr;

	/* IPv6 is disabled in this interface. */
	if (!id->id_mv6)
		return 0;

	if (in6 == NULL)
		log_debug("%s: %s (%d) group all_routers",
		    __func__, id->id_name, id->id_vindex6);
	else
		log_debug("%s: %s (%d) group %s",
		    __func__, id->id_name, id->id_vindex6, addr6tostr(in6));

	ipv6mr.ipv6mr_multiaddr = (in6 == NULL) ? in6_allrouters : *in6;
	ipv6mr.ipv6mr_interface = id->id_index;
	if (setsockopt(mldsd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &ipv6mr,
	    sizeof(ipv6mr)) == -1) {
		log_warn("%s: setsockopt IPV6_LEAVE_GROUP: %s",
		    __func__, strerror(errno));
		return -1;
	}

	return 0;
}

int
mcast_addroute(unsigned short pvidx, union uaddr *origin,
    union uaddr *group, struct molist *molist)
{
	struct intf_data	*id;
	struct multicast_origin	*mo;
	struct mfcctl		 mfcc;
	unsigned short		 vidx;

	memset(&mfcc, 0, sizeof(mfcc));
	mfcc.mfcc_origin = origin->v4;
	mfcc.mfcc_mcastgrp = group->v4;
	mfcc.mfcc_parent = pvidx;
	LIST_FOREACH(mo, molist, mo_entry) {
		id = mo->mo_id;

		/* Don't set upstream interface TTL. */
		if (id == upstreamif)
			continue;

		vidx = id->id_vindex;
		if (vidx > MAXVIFS)
			continue;

		mfcc.mfcc_ttls[vidx] = id->id_ttl;
	}

	log_debug("%s: add route origin %s group %s parent %d",
	    __func__, addr4tostr(&origin->v4), addr4tostr(&group->v4),
	    pvidx);

	LIST_FOREACH(mo, molist, mo_entry) {
		id = mo->mo_id;
		vidx = id->id_vindex;
		if (vidx > MAXVIFS)
			continue;

		if (mfcc.mfcc_ttls[vidx])
			log_debug("  vif %s (%d) ttl %d",
			    id->id_name, vidx, mfcc.mfcc_ttls[vidx]);
		else
			log_debug("  vif %s (%d) disabled",
			    id->id_name, vidx);
	}


	if (setsockopt(igmpsd, IPPROTO_IP, MRT_ADD_MFC, &mfcc,
	    sizeof(mfcc)) == -1) {
		log_warn("%s: setsockopt MRT_ADD_MFC", __func__);
		return -1;
	}

	return 0;
}

int
mcast_addroute6(unsigned short pvidx, union uaddr *origin,
    union uaddr *group, struct molist *molist)
{
	struct intf_data	*id;
	struct multicast_origin	*mo;
	struct mf6cctl		 mf6cc;
	unsigned short		 vidx;

	memset(&mf6cc, 0, sizeof(mf6cc));
	mf6cc.mf6cc_parent = pvidx;
	mf6cc.mf6cc_origin.sin6_family = AF_INET6;
	mf6cc.mf6cc_origin.sin6_addr = origin->v6;
	mf6cc.mf6cc_origin.sin6_len = sizeof(mf6cc.mf6cc_origin);
	mf6cc.mf6cc_mcastgrp.sin6_family = AF_INET6;
	mf6cc.mf6cc_mcastgrp.sin6_addr = group->v6;
	mf6cc.mf6cc_mcastgrp.sin6_len = sizeof(mf6cc.mf6cc_mcastgrp);
	LIST_FOREACH(mo, molist, mo_entry) {
		id = mo->mo_id;

		/* Don't set upstream interface. */
		if (id == upstreamif)
			continue;

		vidx = id->id_vindex6;
		if (vidx > MAXMIFS)
			continue;

		IF_SET(vidx, &mf6cc.mf6cc_ifset);
	}

	log_debug("%s: add route origin %s group %s parent %d",
	    __func__, addr6tostr(&origin->v6), addr6tostr(&group->v6),
	    pvidx);

	LIST_FOREACH(mo, molist, mo_entry) {
		id = mo->mo_id;
		vidx = id->id_vindex6;
		if (vidx > MAXMIFS)
			continue;

		if (IF_ISSET(vidx, &mf6cc.mf6cc_ifset))
			log_debug("  mif %s (%d)",
			    id->id_name, vidx);
		else
			log_debug("  mif %s (%d) disabled",
			    id->id_name, vidx);
	}


	if (setsockopt(mldsd, IPPROTO_IPV6, MRT6_ADD_MFC, &mf6cc,
	    sizeof(mf6cc)) == -1) {
		log_warn("%s: setsockopt MRT6_ADD_MFC", __func__);
		return -1;
	}

	return 0;
}

int
mcast_delroute(unsigned short pvidx, union uaddr *origin,
    union uaddr *group)
{
	struct mfcctl		 mfcc;

	memset(&mfcc, 0, sizeof(mfcc));
	mfcc.mfcc_origin = origin->v4;
	mfcc.mfcc_mcastgrp = group->v4;
	mfcc.mfcc_parent = pvidx;

	log_debug("%s: del route origin %s group %s parent %d",
	    __func__, addr4tostr(&origin->v4), addr4tostr(&group->v4),
	    pvidx);

	if (setsockopt(igmpsd, IPPROTO_IP, MRT_DEL_MFC, &mfcc,
	    sizeof(mfcc)) == -1) {
		log_warn("%s: setsockopt MRT_DEL_MFC", __func__);
		return -1;
	}

	return 0;
}

int
mcast_delroute6(unsigned short pvidx, union uaddr *origin,
    union uaddr *group)
{
	struct mf6cctl		 mf6cc;

	memset(&mf6cc, 0, sizeof(mf6cc));
	mf6cc.mf6cc_parent = pvidx;
	mf6cc.mf6cc_origin.sin6_addr = origin->v6;
	mf6cc.mf6cc_mcastgrp.sin6_addr = group->v6;

	log_debug("%s: del route origin %s group %s parent %d",
	    __func__, addr6tostr(&origin->v6), addr6tostr(&group->v6),
	    pvidx);

	if (setsockopt(mldsd, IPPROTO_IPV6, MRT6_DEL_MFC, &mf6cc,
	    sizeof(mf6cc)) == -1) {
		log_warn("%s: setsockopt MRT_DEL6_MFC", __func__);
		return -1;
	}

	return 0;
}

void
intf_dispatch(int sd, __unused short ev, __unused void *arg)
{
	ssize_t		 n;
	uint8_t		 buf[rtsd_rcvbuf];

	if ((n = read(sd, buf, rtsd_rcvbuf)) == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			log_warn("%s: read", __func__);

		return;
	}

	if (n == 0)
		fatalx("%s: routing socket closed", __func__);

	rtmsg_process(buf, n);
}

int
intf_init(void)
{
	size_t		 len;
	int		 mib[6];
	uint8_t		*buf;
	int		 sd, opt, rcvbuf, defrcvbuf;
	socklen_t	 optlen;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = 0;	/* wildcard */
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
		fatal("%s: sysctl", __func__);
	if ((buf = malloc(len)) == NULL)
		fatal("%s: malloc", __func__);
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		free(buf);
		fatal("%s: sysctl", __func__);
	}

	rtmsg_process(buf, len);
	free(buf);

	sd = socket(AF_ROUTE, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sd == -1)
		fatal("%s: socket", __func__);

	opt = 0;
	if (setsockopt(sd, SOL_SOCKET, SO_USELOOPBACK,
	    &opt, sizeof(opt)) == -1)
		fatal("%s: setsockopt SO_USELOOPBACK", __func__);

	/* Increase the receive buffer. */
	rcvbuf = MAX_RTSOCK_BUF;
	optlen = sizeof(rcvbuf);
	if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF,
	    &defrcvbuf, &optlen) == -1)
		log_warn("%s: getsockopt SO_RCVBUF", __func__);
	else
		for (; rcvbuf > defrcvbuf &&
		    setsockopt(sd, SOL_SOCKET, SO_RCVBUF,
		    &rcvbuf, sizeof(rcvbuf)) == -1 && errno == ENOBUFS;
		    rcvbuf /= 2)
			continue;

	rtsd_rcvbuf = rcvbuf;

	return (sd);
}

void
if_announce(struct if_announcemsghdr *ifan)
{
	struct intf_data	*id;

	if (ifan->ifan_what == IFAN_DEPARTURE) {
		log_debug("%s departure: %s", __func__, ifan->ifan_name);

		id = intf_lookupbyname(ifan->ifan_name);
		if (id == NULL)
			return;

		id->id_enabled = 0;
		id->id_vindex = INVALID_VINDEX;
		id->id_vindex6 = INVALID_VINDEX;
		return;
	} else
		log_debug("%s arrival: %s", __func__, ifan->ifan_name);

	id = intf_lookupbyname(ifan->ifan_name);
	if (id == NULL) {
		id = id_insert(ifan->ifan_index);
		if (id == NULL)
			return;
	}

	id->id_index = ifan->ifan_index;
	strlcpy(id->id_name, ifan->ifan_name, sizeof(id->id_name));
}

void
if_update(unsigned short ifindex, int flags, struct if_data *ifd,
    struct sockaddr_dl *sdl)
{
	struct intf_data	*id;
	size_t			 sdllen = 0;
	char			 ifname[IFNAMSIZ];

	/* Don't install loopback interfaces. */
	if ((flags & IFF_LOOPBACK) == IFF_LOOPBACK)
		return;
	/* Don't install non multicast interfaces. */
	if ((flags & IFF_MULTICAST) != IFF_MULTICAST)
		return;

	/* Check for sdl and copy interface name. */
	if (sdl == NULL || sdl->sdl_family != AF_LINK)
		goto insert_interface;

	sdllen = (sdl->sdl_nlen >= sizeof(id->id_name)) ?
	    (sizeof(id->id_name) - 1) : sdl->sdl_nlen;

	memcpy(ifname, sdl->sdl_data, sdllen);
	ifname[sdllen] = 0;

	log_debug("%s: if %s (%d)", __func__, ifname, ifindex);

	id = intf_lookupbyname(ifname);
	if (id == NULL) {
 insert_interface:
		id = id_insert(ifindex);
		if (id == NULL)
			return;
	}

	id->id_enabled = (flags & IFF_UP) &&
	    LINK_STATE_IS_UP(ifd->ifi_link_state);
	id->id_index = ifindex;
	id->id_flags = flags;
	id->id_rdomain = ifd->ifi_rdomain;
	if (sdllen > 0)
		strlcpy(id->id_name, ifname, sizeof(id->id_name));
}

int
bad_addr_v4(struct in_addr addr)
{
	uint32_t	 a = ntohl(addr.s_addr);

	if (((a >> IN_CLASSA_NSHIFT) == 0) ||
	    ((a >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET) ||
	    IN_MULTICAST(a) || IN_BADCLASS(a))
		return (1);

	return (0);
}

int
bad_addr_v6(struct in6_addr *addr)
{
	if (IN6_IS_ADDR_UNSPECIFIED(addr) ||
	    IN6_IS_ADDR_LOOPBACK(addr) ||
	    IN6_IS_ADDR_MULTICAST(addr) ||
	    IN6_IS_ADDR_SITELOCAL(addr) ||
	    IN6_IS_ADDR_V4MAPPED(addr) ||
	    IN6_IS_ADDR_V4COMPAT(addr))
		return (1);

	return (0);
}

void
if_newaddr(unsigned short ifindex, struct sockaddr *ifa, struct sockaddr *mask)
{
	struct intf_data	*id;
	struct intf_addr	*ia;
	struct sockaddr_in	*ifa4, *mask4;
	struct sockaddr_in6	*ifa6, *mask6;
	int			 newaddr;

	if (ifa == NULL)
		return;

	id = intf_lookupbyindex(ifindex);
	if (id == NULL) {
		log_debug("%s: corresponding if %d not found",
		    __func__, ifindex);
		return;
	}

	switch (ifa->sa_family) {
	case AF_INET:
		ifa4 = (struct sockaddr_in *) ifa;
		mask4 = (struct sockaddr_in *) mask;

		/* filter out unwanted addresses */
		if (bad_addr_v4(ifa4->sin_addr))
			return;

		ia = calloc(1, sizeof(*ia));
		if (ia == NULL)
			fatal("%s: calloc", __func__);

		ia->ia_addr.v4 = ifa4->sin_addr;
		if (mask4)
			ia->ia_prefixlen =
			    mask2prefixlen(mask4->sin_addr.s_addr);

		log_debug("%s: if %s (%d): %s (prefixlen %d)",
		    __func__, id->id_name, id->id_index,
		    addr4tostr(&ifa4->sin_addr), ia->ia_prefixlen);
		break;
	case AF_INET6:
		ifa6 = (struct sockaddr_in6 *) ifa;
		mask6 = (struct sockaddr_in6 *) mask;

		/* We only care about link-local and global-scope. */
		if (bad_addr_v6(&ifa6->sin6_addr))
			return;

		ia = calloc(1, sizeof(*ia));
		if (ia == NULL)
			fatal("%s: calloc", __func__);

		ia->ia_addr.v6 = ifa6->sin6_addr;
		if (mask6)
			ia->ia_prefixlen = mask2prefixlen6(mask6);

		log_debug("%s: if %s (%d): %s (prefixlen %d)",
		    __func__, id->id_name, id->id_index,
		    addr6tostr(&ifa6->sin6_addr), ia->ia_prefixlen);
		break;
	default:
		return;
	}

	newaddr = (intf_primaryv4(id) == NULL);

	ia->ia_af = ifa->sa_family;
	ia_inserttail(&id->id_ialist, ia);

	/*
	 * Register interface if it is a new primary address in a
	 * enabled interface.
	 */
	if (newaddr && id->id_dir != IDIR_DISABLE) {
		vif_register(id);
		if (id->id_dir == IDIR_DOWNSTREAM)
			mcast_join(id, NULL);
	}
}

int
iacmp(struct intf_addr *ia, struct intf_addr *ian)
{
	if (ia->ia_af > ian->ia_af)
		return -1;

	return memcmp(&ia->ia_addr, &ian->ia_addr, (ia->ia_af == AF_INET) ?
	    sizeof(ia->ia_addr.v4) : sizeof(ia->ia_addr.v6));
}

void
if_deladdr(unsigned short ifindex, struct sockaddr *ifa, struct sockaddr *mask)
{
	struct intf_data	*id;
	struct intf_addr	 iac, *ia;
	struct sockaddr_in	*ifa4, *mask4;
	struct sockaddr_in6	*ifa6, *mask6;
	int			 regagain = 0;

	if (ifa == NULL)
		return;

	id = intf_lookupbyindex(ifindex);
	if (id == NULL) {
		log_debug("%s: corresponding if %d not found",
		    __func__, ifindex);
		return;
	}

	memset(&iac, 0, sizeof(iac));
	iac.ia_af = ifa->sa_family;
	switch (ifa->sa_family) {
	case AF_INET:
		ifa4 = (struct sockaddr_in *) ifa;
		mask4 = (struct sockaddr_in *) mask;

		/* filter out unwanted addresses */
		if (bad_addr_v4(ifa4->sin_addr))
			return;

		iac.ia_addr.v4 = ifa4->sin_addr;
		if (mask4)
			iac.ia_prefixlen =
			    mask2prefixlen(mask4->sin_addr.s_addr);

		log_debug("%s: if %s (%d): %s (prefixlen %d)",
		    __func__, id->id_name, id->id_index,
		    addr4tostr(&ifa4->sin_addr), iac.ia_prefixlen);
		break;
	case AF_INET6:
		ifa6 = (struct sockaddr_in6 *) ifa;
		mask6 = (struct sockaddr_in6 *) mask;

		/* We only care about link-local and global-scope. */
		if (bad_addr_v6(&ifa6->sin6_addr))
			return;

		iac.ia_addr.v6 = ifa6->sin6_addr;
		if (mask6)
			iac.ia_prefixlen = mask2prefixlen6(mask6);

		log_debug("%s: if %s (%d): %s (prefixlen %d)",
		    __func__, id->id_name, id->id_index,
		    addr6tostr(&ifa6->sin6_addr), iac.ia_prefixlen);
		break;
	default:
		return;
	}

	SLIST_FOREACH(ia, &id->id_ialist, ia_entry) {
		if (ia->ia_af != iac.ia_af ||
		    ia->ia_prefixlen != iac.ia_prefixlen ||
		    iacmp(ia, &iac))
			continue;

		/*
		 * Unregister the interface if this is a primary
		 * address, then check for new primary address.
		 */
		if (ia->ia_af == AF_INET && ia == intf_primaryv4(id)) {
			vif4_unregister(id);
			if (intf_primaryv4(id) != NULL)
				regagain = 1;
		}

		SLIST_REMOVE(&id->id_ialist, ia, intf_addr, ia_entry);
		free(ia);

		/* Re-register if there is a new primary address. */
		if (regagain)
			vif4_register(id);
		return;
	}
}

#define	ROUNDUP(a)	\
    (((a) & (sizeof(long) - 1)) ? (1 + ((a) | (sizeof(long) - 1))) : (a))

void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len));
		} else
			rti_info[i] = NULL;
	}
}

void
rtmsg_process(const uint8_t *buf, size_t len)
{
	struct rt_msghdr	*rtm;
	struct if_msghdr	 ifm;
	struct ifa_msghdr	*ifam;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];
	size_t			 offset;
	const uint8_t		*next;

	for (offset = 0; offset < len; offset += rtm->rtm_msglen) {
		next = buf + offset;
		rtm = (struct rt_msghdr *)next;
		if (len < offset + sizeof(unsigned short) ||
		    len < offset + rtm->rtm_msglen)
			fatalx("%s: partial RTM in buffer", __func__);
		if (rtm->rtm_version != RTM_VERSION)
			continue;

		sa = (struct sockaddr *)(next + rtm->rtm_hdrlen);
		get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			memcpy(&ifm, next, sizeof(ifm));
			if_update(ifm.ifm_index, ifm.ifm_flags, &ifm.ifm_data,
			    (struct sockaddr_dl *)rti_info[RTAX_IFP]);
			break;
		case RTM_NEWADDR:
			ifam = (struct ifa_msghdr *)rtm;
			if ((ifam->ifam_addrs & (RTA_NETMASK | RTA_IFA |
			    RTA_BRD)) == 0)
				break;

			if_newaddr(ifam->ifam_index,
			    (struct sockaddr *)rti_info[RTAX_IFA],
			    (struct sockaddr *)rti_info[RTAX_NETMASK]);
			break;
		case RTM_DELADDR:
			ifam = (struct ifa_msghdr *)rtm;
			if ((ifam->ifam_addrs & (RTA_NETMASK | RTA_IFA |
			    RTA_BRD)) == 0)
				break;

			if_deladdr(ifam->ifam_index,
			    (struct sockaddr *)rti_info[RTAX_IFA],
			    (struct sockaddr *)rti_info[RTAX_NETMASK]);
			break;
		case RTM_IFANNOUNCE:
			if_announce((struct if_announcemsghdr *)next);
			break;
		default:
			break;
		}
	}
}
