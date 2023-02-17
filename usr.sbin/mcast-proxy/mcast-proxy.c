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

#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>

#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mcast-proxy.h"

__dead void usage(void);
__dead void daemon_shutdown(void);
void sighandler(int, short, void *);
void config_setdefaults(void);

int mcast_mquery4(struct intf_data *, struct in_addr *, struct in_addr *);
int mcast_mquery6(struct intf_data *, struct in6_addr *, struct in6_addr *);
int build_packet(uint8_t *, size_t *, struct intf_data *, struct in_addr *,
    struct in_addr *, uint8_t, uint8_t);
int build_packet6(uint8_t *, size_t *, struct intf_data *,
    struct in6_addr *, uint8_t, uint8_t);
int kernel_parse(uint8_t *, size_t);
int kernel_parsev6(uint8_t *, size_t);
struct igmp *igmp_parse(uint8_t *, size_t *, struct sockaddr_storage *);
const char *igmptypetostr(uint16_t);
void intf_setup(void);
void send_generalmquery(int, short, void *);
void igmp_recv(int, short, void *);
const char *mldtypetostr(uint16_t);
int mld_parse(struct intf_data *, struct sockaddr_storage *, uint8_t *,
    size_t);
void mld_recv(int, short, void *);

struct iflist		 iflist;
struct intf_data	*upstreamif;
int			 igmpsd = -1;
int			 mldsd = -1;

const char		*config_file = "/etc/mcast-proxy.conf";
struct igmpproxy_conf	 ic;

int
main(int argc, char *argv[])
{
	struct passwd	*pw;
	int		 verbose = 0, daemonize = 1, noaction = 0;
	int		 ch, intfsd;
	struct timeval	 qtv = { IGMP_STARTUP_QUERY_INTERVAL, 0 };
	struct event	 igmpev, mldev, intfev, qtimerev;
	struct event	 hupev, termev, intev;

	config_setdefaults();

	/* Load all system interfaces and get their information. */
	intfsd = intf_init();

	/* Initiate with verbose logging. */
	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	while ((ch = getopt(argc, argv, "f:D:dnv")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
                                    optarg);
			break;
		case 'd':
			daemonize = 0;
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'n':
			noaction = 1;
			break;
		case 'v':
			verbose = 2;
			break;
		default:
			usage();
			break;
		}
	}

	if (parse_config(config_file) == -1)
		fatalx("configuration failed");

	if (noaction)
		exit(0);

	/* Assert that we can run multicast forwarding. */
	assert_mcastforward();

	/* Create the IGMP socket. */
	if (ic.ic_ipv4)
		igmpsd = open_igmp_socket();
	if (ic.ic_ipv6)
		mldsd = open_mld_socket();

	/* Drop privileges. */
	pw = getpwnam(MCAST_PROXY_USER);
	if (pw == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("privilege drop");

	/* Use the configured logging verbosity. */
	log_init(!daemonize, LOG_DAEMON);
	log_setverbose(verbose);

	if (daemonize)
		daemon(0, 0);

	log_info("startup");

	/* Initialize libevent. */
	event_init();

	/* Install signal handlers. */
	signal_set(&hupev, SIGHUP, sighandler, NULL);
	signal_set(&intev, SIGINT, sighandler, NULL);
	signal_set(&termev, SIGTERM, sighandler, NULL);
	signal_add(&hupev, NULL);
	signal_add(&intev, NULL);
	signal_add(&termev, NULL);
	signal(SIGPIPE, SIG_IGN);

	event_set(&igmpev, igmpsd, EV_READ | EV_PERSIST,
	    igmp_recv, NULL);
	event_add(&igmpev, NULL);
	event_set(&mldev, mldsd, EV_READ | EV_PERSIST,
	    mld_recv, NULL);
	event_add(&mldev, NULL);
	event_set(&intfev, intfsd, EV_READ | EV_PERSIST,
	    intf_dispatch, NULL);
	event_add(&intfev, NULL);

	evtimer_set(&qtimerev, send_generalmquery, &qtimerev);
	evtimer_add(&qtimerev, &qtv);

	/* Initialize interfaces IGMP reception. */
	intf_setup();

#if 0
	if (pledge("stdio inet", NULL) != 0)
		fatal("pledge");
#endif

	/* Send the startup query. */
	send_generalmquery(0, 0, &qtimerev);

	event_dispatch();

	daemon_shutdown();

	return 0;
}

__dead void
usage(void)
{
	extern const char	*__progname;

	fprintf(stderr, "%s: [-dnv] [-D macro=value] [-f config]\n",
	    __progname);

	exit(1);
}

__dead void
daemon_shutdown(void)
{
	struct intf_data	*id;
	int			 error = 0;

	/* Clean up routes to make sure no interface references exist. */
	mrt_cleanup();
	upstreamif = NULL;

	/* Remove all interfaces. */
	while (!SLIST_EMPTY(&iflist)) {
		id = SLIST_FIRST(&iflist);
		id_free(id);
	}

	/* Close multicast sockets. */
	error |= close_igmp_socket(igmpsd);
	error |= close_mld_socket(mldsd);
	igmpsd = -1;
	mldsd = -1;

	exit(error != 0);
}

void
sighandler(int sig, __unused short ev, __unused void *arg)
{
	switch (sig) {
	case SIGHUP:
		/* FALLTHROUGH */
	case SIGTERM:
	case SIGINT:
		log_info("received signal %d", sig);
		daemon_shutdown();
		break;
	}
}

void
config_setdefaults(void)
{
	ic.ic_ipv4 = 1;
	ic.ic_ipv6 = 0;
}

const char *
igmptypetostr(uint16_t type)
{
	switch (type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		return "MEMBERSHIP_QUERY";
	case IGMP_v1_HOST_MEMBERSHIP_REPORT:
		return "MEMBERSHIP_REPORT_V1";
	case IGMP_v2_HOST_MEMBERSHIP_REPORT:
		return "MEMBERSHIP_REPORT_V2";
	case IGMP_HOST_LEAVE_MESSAGE:
		return "LEAVE";

	default:
		return "unknown";
	}
}

int
build_packet(uint8_t *p, size_t *plen, struct intf_data *id,
    struct in_addr *dst, struct in_addr *grp, uint8_t type, uint8_t code)
{
	struct ip		*ip = (struct ip *)p;
	struct intf_addr	*ia;
	struct igmp		*igmp;
	uint8_t			 hlen;

	*plen = 0;

	if ((ia = intf_primaryv4(id)) == NULL) {
		log_debug("%s doesn't have an address", id->id_name);
		return -1;
	}

	memset(ip, 0, sizeof(*ip));
	hlen = sizeof(*ip) >> 2;
	ip->ip_hl = hlen;
	ip->ip_v = IPVERSION;
	ip->ip_tos = IPTOS_PREC_INTERNETCONTROL;
	ip->ip_ttl = IPDEFTTL;
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_src = ia->ia_addr.v4;
	ip->ip_dst = *dst;
	*plen = hlen << 2;

	igmp = (struct igmp *)(p + sizeof(*ip));
	igmp->igmp_type = type;
	igmp->igmp_code = code;
	igmp->igmp_cksum = 0;
	igmp->igmp_group = *grp;
	*plen += sizeof(*igmp);

	/* Calculate the IP checksum. */
	ip->ip_len = htons(*plen);
	ip->ip_sum = wrapsum(checksum((uint8_t *)ip, hlen, 0));

	/* Calculate the IGMP checksum. */
	igmp->igmp_cksum = wrapsum(checksum((uint8_t *)igmp,
	    sizeof(*igmp), 0));

	return 0;
}

int
mcast_mquery4(struct intf_data *id, struct in_addr *dst, struct in_addr *grp)
{
	struct intf_addr	*ia;
	size_t			 blen;
	ssize_t			 bsent;
	struct sockaddr_storage	 to;
	uint8_t			 b[2048];

	if ((ia = intf_primaryv4(id)) == NULL) {
		log_debug("%s doesn't have an address", id->id_name);
		return -1;
	}

	blen = sizeof(b);
	if (build_packet(b, &blen, id, dst, grp, IGMP_HOST_MEMBERSHIP_QUERY,
	    IGMP_RESPONSE_INTERVAL * IGMP_TIMER_SCALE) == -1) {
		log_debug("%s: packet build failed", __func__);
		return -1;
	}

	igmp_setif(id);

	to.ss_family = AF_INET;
	to.ss_len = sizeof(struct sockaddr_in);
	sstosin(&to)->sin_addr = *dst;
	if ((bsent = sendto(igmpsd, b, blen, 0, (struct sockaddr *)&to,
	    to.ss_len)) == -1) {
		log_warn("send IGMP %s (via %s) to %s",
		    addr4tostr(&ia->ia_addr.v4), id->id_name, addrtostr(&to));
		return -1;
	}

	igmp_setif(NULL);

	log_debug("%s (%s) -> %s IGMP MEMBERSHIP_QUERY %ld bytes",
	    addr4tostr(&ia->ia_addr.v4), id->id_name, addrtostr(&to),
	    bsent);

	return 0;
}

int
build_packet6(uint8_t *p, size_t *plen, struct intf_data *id,
    struct in6_addr *grp, uint8_t type, uint8_t code)
{
	struct intf_addr	*ia;
	struct mld_hdr		*mld;

	*plen = 0;

	if ((ia = intf_ipv6linklayer(id)) == NULL) {
		log_debug("%s doesn't have an address", id->id_name);
		return -1;
	}

	mld = (struct mld_hdr *)p;
	mld->mld_type = type;
	mld->mld_code = code;
	mld->mld_cksum = 0;
	mld->mld_maxdelay = 0;
	mld->mld_reserved = 0;
	mld->mld_addr = *grp;
	*plen += sizeof(*mld);

	return 0;
}

int
mcast_mquery6(struct intf_data *id, struct in6_addr *dst,
    struct in6_addr *grp)
{
	struct intf_addr	*ia;
	struct cmsghdr		*cmsg;
	struct in6_pktinfo	*ipi6;
	size_t			 blen;
	ssize_t			 bsent;
	struct msghdr		 msg;
	struct sockaddr_storage	 to;
	struct iovec		 iov[1];
	uint8_t			 b[2048];
	uint8_t			 cmsgbuf[
	    CMSG_SPACE(sizeof(struct in6_pktinfo))
	];

	if ((ia = intf_ipv6linklayer(id)) == NULL) {
		log_debug("%s doesn't have an address", id->id_name);
		return -1;
	}

	blen = sizeof(b);
	if (build_packet6(b, &blen, id, grp, MLD_LISTENER_QUERY, 0) == -1) {
		log_debug("%s: packet build failed", __func__);
		return -1;
	}

	to.ss_family = AF_INET6;
	to.ss_len = sizeof(struct sockaddr_in6);
	sstosin6(&to)->sin6_addr = *dst;

	/* Populate msghdr. */
	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = b;
	iov[0].iov_len = blen;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &to;
	msg.msg_namelen = sizeof(struct sockaddr_in6);

	/* Populate msghdr parameters. */
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	/* Use the IPV6_PKTINFO to select the interface. */
	cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*ipi6));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;

	/* Set output interface */
	ipi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	ipi6->ipi6_ifindex = id->id_index;

	if ((bsent = sendmsg(mldsd, &msg, 0)) == -1) {
		log_warn("MLD %s (via %s) to %s",
		    addr6tostr(&ia->ia_addr.v6), id->id_name, addrtostr(&to));
		return -1;
	}

	log_debug("%s (%s) -> %s MLD MEMBERSHIP_QUERY %ld bytes",
	    addr6tostr(&ia->ia_addr.v6), id->id_name, addrtostr(&to),
	    bsent);

	return 0;
}

int
kernel_parse(uint8_t *p, size_t plen)
{
	struct intf_addr	*ia;
	struct intf_data	*id;
	struct ip		*ip = (struct ip *)p;

	/* Sanity check: do we have enough data to work with? */
	if (plen < sizeof(*ip)) {
		log_debug("%s: insufficient packet size", __func__);
		return 0;
	}

	/* Validate upstream interface current state. */
	if (upstreamif == NULL) {
		log_debug("%s: no upstream interface", __func__);
		return 0;
	}
	if ((ia = intf_primaryv4(upstreamif)) == NULL) {
		log_debug("%s: no upstream interface address", __func__);
		return 0;
	}

	if (ip->ip_src.s_addr == INADDR_ANY ||
	    ip->ip_dst.s_addr == INADDR_ANY) {
		log_debug("%s: invalid packet addresses", __func__);
		return 0;
	}

	/* We only handle kernel messages here. */
	if (ip->ip_p != IPPROTO_IP)
		return -1;

	id = intf_lookupbyaddr4(ip->ip_src.s_addr);
	if (id == NULL || !id->id_enabled) {
		log_debug("%s: no interface matches origin", __func__);
		return 0;
	}

	mrt_insert4(MV_IGMPV3, id, &ip->ip_src, &ip->ip_dst);

	return 0;
}

struct igmp *
igmp_parse(uint8_t *p, size_t *plen, struct sockaddr_storage *src)
{
	struct ip		*ip = (struct ip *)p;
	size_t			 hlen, ptotal;
	uint16_t		 cksum;

	if (ip->ip_p != IPPROTO_IGMP) {
		log_debug("%s: expected IGMP message, got %d",
		    __func__, ip->ip_p);
		return NULL;
	}

	/* IP header validations. */
	if (ip->ip_v != IPVERSION) {
		log_debug("%s: wrong IP version", __func__);
		return 0;
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(*ip)) {
		log_debug("%s: wrong IP header length", __func__);
		return 0;
	}
	if ((ip->ip_off & htons(IP_OFFMASK)) != 0) {
		log_debug("%s: fragmented packet", __func__);
		return 0;
	}
	if (ip->ip_ttl == 0) {
		log_debug("%s: invalid TTL", __func__);
		return 0;
	}

	hlen = ip->ip_hl << 2;

	ptotal = ntohs(ip->ip_len);
	if (*plen != ptotal) {
		log_debug("%s: IP header length different than packet "
		    "(%ld vs %ld)", __func__, ptotal, *plen);
		return 0;
	}

	cksum = wrapsum(checksum((uint8_t *)ip, hlen, 0));
	if (cksum != 0) {
		log_debug("%s: IP checksum is invalid", __func__);
		return NULL;
	}

	cksum = wrapsum(checksum((uint8_t *)ip, *plen, 0));
	if (cksum != 0) {
		log_debug("%s: IGMP invalid checksum", __func__);
		return NULL;
	}

	log_debug("IGMP (IPv%d) %s -> %s %ld bytes",
	    ip->ip_v, addr4tostr(&ip->ip_src), addr4tostr(&ip->ip_dst),
	    *plen);

	/* Return the source address and update the remaining size. */
	memset(src, 0, sizeof(*src));
	src->ss_family = AF_INET;
	src->ss_len = sizeof(struct sockaddr_in);
	sstosin(src)->sin_addr = ip->ip_src;

	*plen -= hlen;

	return ((struct igmp *)(p + hlen));
}

void
igmp_recv(int fd, __unused short ev, __unused void *arg)
{
	struct igmp		*igmp;
	struct intf_data	*id;
	ssize_t			 rlen;
	struct sockaddr_storage	 src;
	uint8_t			 p[2048];

	if ((rlen = recv(fd, p, sizeof(p), 0)) == -1) {
		log_warn("%s: recv", __func__);
		return;
	}
	/* Check for kernel messages and do IP header validations. */
	if (kernel_parse(p, rlen) == 0 ||
	    (igmp = igmp_parse(p, &rlen, &src)) == NULL)
		return;

	/* Handle the IGMP packet. */
	if ((size_t)rlen < sizeof(*igmp)) {
		log_debug("%s: IGMP packet too short", __func__);
		return;
	}

	log_debug("  %s: code %d group %s",
	    igmptypetostr(igmp->igmp_type), igmp->igmp_code,
	    addr4tostr(&igmp->igmp_group));

	/* Sanity check: group is always multicast address. */
	if (!IN_MULTICAST(ntohl(igmp->igmp_group.s_addr))) {
		log_debug("%s: group is not a multicast address",
		    __func__);
		return;
	}

	/* Determine from which interface this packet came from. */
	id = intf_lookupbyaddr4(sstosin(&src)->sin_addr.s_addr);
	if (id == NULL || !id->id_enabled) {
		log_debug("%s: no interface matches origin", __func__);
		return;
	}

	/* Don't receive commands from upstream interface. */
	if (id == upstreamif) {
		log_debug("%s: ignoring host command on upstream interface",
		   __func__);
		return;
	}

	switch (igmp->igmp_type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		break;
	case IGMP_v1_HOST_MEMBERSHIP_REPORT:
		mrt_insert4(MV_IGMPV1, id, &sstosin(&src)->sin_addr,
		    &igmp->igmp_group);
		break;
	case IGMP_v2_HOST_MEMBERSHIP_REPORT:
		mrt_insert4(MV_IGMPV2, id, &sstosin(&src)->sin_addr,
		    &igmp->igmp_group);
		break;
	case IGMP_HOST_LEAVE_MESSAGE:
		mrt_remove4(id, &sstosin(&src)->sin_addr, &igmp->igmp_group);
		break;
	}
}

const char *
mldtypetostr(uint16_t type)
{
	switch (type) {
	case MLD_LISTENER_QUERY:
		return "LISTENER_QUERY";
	case MLD_LISTENER_REPORT:
		return "LISTENER_REPORT";
	case MLD_LISTENER_DONE:
		return "LISTENER_DONE";

	default:
		return "unknown";
	}
}

int
kernel_parsev6(uint8_t *p, size_t plen)
{
	struct ip6_hdr		*ip6 = (struct ip6_hdr *)p;
	struct intf_data	*id;

	/* Sanity checks:
	 * - packet size (ipv6 header)
	 * - multicast destination
	 */
	if (plen < sizeof(*ip6)) {
		log_debug("%s: packet too small for IPv6 header", __func__);
		return -1;
	}
	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		log_debug("%s: not a multicast packet", __func__);
		return -1;
	}

	id = intf_lookupbyaddr6(&ip6->ip6_src);
	if (id == NULL || !id->id_enabled) {
		log_debug("%s: no input interface for %s",
		    __func__, addr6tostr(&ip6->ip6_src));
		return -1;
	}

	log_debug("IPv6 %s (%s) -> %s",
	    addr6tostr(&ip6->ip6_src), id->id_name,
	    addr6tostr(&ip6->ip6_dst));

	mrt_insert6(MV_IGMPV3, id, &ip6->ip6_src, &ip6->ip6_dst);

	return 0;
}

int
mld_parse(struct intf_data *id, struct sockaddr_storage *src,
    uint8_t *p, size_t plen)
{
	struct mld_hdr			*mld = (struct mld_hdr *)p;

	if (plen < sizeof(*mld)) {
		log_debug("%s: packet too small", __func__);
		return -1;
	}

	log_debug("MLD %s %s -> %s", mldtypetostr(mld->mld_type),
	    addrtostr(src), addr6tostr(&mld->mld_addr));

	switch (mld->mld_type) {
	case MLD_LISTENER_QUERY:
		break;
	case MLD_LISTENER_REPORT:
		mrt_insert6(MV_IGMPV2, id, &sstosin6(src)->sin6_addr,
		    &mld->mld_addr);
		break;
	case MLD_LISTENER_DONE:
		mrt_remove6(id, &sstosin6(src)->sin6_addr, &mld->mld_addr);
		break;

	default:
		log_debug("%s: invalid MLD type %d",
		    __func__, mld->mld_type);
		break;
	}

	return 0;
}

void
mld_recv(int sd, __unused short ev, __unused void *arg)
{
	struct in6_pktinfo		*ipi6 = NULL;
	struct intf_data		*id;
	struct cmsghdr			*cmsg;
	ssize_t				 rlen;
	struct msghdr			 msg;
	struct iovec			 iov[1];
	struct sockaddr_storage		 ss;
	uint8_t				 iovbuf[2048];
	uint8_t				 cmsgbuf[
		CMSG_SPACE(sizeof(*ipi6))
	];

	iov[0].iov_base = iovbuf;
	iov[0].iov_len = sizeof(iovbuf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_name = &ss;
	msg.msg_namelen = sizeof(ss);
	if ((rlen = recvmsg(sd, &msg, 0)) == -1) {
		log_warn("%s: recvmsg", __func__);
		return;
	}

	/* Sanity check: is this IPv6? */
	if (ss.ss_family != AF_INET6) {
		log_debug("%s: received non IPv6 packet", __func__);
		return;
	}

	/* Find out input interface. */
	for (cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg); cmsg;
	    cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			ipi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			break;
		}
	}
	/* Kernel messages from the routing socket don't have PKTINFO. */
	if (ipi6 == NULL) {
		kernel_parsev6(iovbuf, rlen);
		return;
	}

	/* Deal with packets coming from the network. */
	id = intf_lookupbyindex(ipi6->ipi6_ifindex);
	if (id == NULL || !id->id_enabled) {
		log_debug("%s: no input interface for %s",
		    __func__, addrtostr(&ss));
		return;
	}

	/* Don't receive commands from upstream interface. */
	if (id == upstreamif) {
		log_debug("%s: ignoring host on upstream interface",
		    __func__);
		return;
	}

	mld_parse(id, &ss, iovbuf, rlen);
}

void
send_generalmquery(__unused int sd, short ev, void *arg)
{
	struct event			*qtimerev = (struct event *)arg;
	struct intf_data		*id;
	struct timeval			 qtv = { IGMP_RESPONSE_INTERVAL, 0 };
	struct in_addr			 allhostsgrp, zerogrp;
	struct in6_addr			 allhostsgrp6 =
	    IN6ADDR_LINKLOCAL_ALLNODES_INIT;
	struct in6_addr			 zerogrp6 = IN6ADDR_ANY_INIT;

	allhostsgrp.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	zerogrp.s_addr = 0;

	SLIST_FOREACH(id, &iflist, id_entry) {
		/* Only join downstream interfaces. */
		if (id->id_dir != IDIR_DOWNSTREAM)
			continue;

		if (id->id_mv4)
			mcast_mquery4(id, &allhostsgrp, &zerogrp);
		if (id->id_mv6)
			mcast_mquery6(id, &allhostsgrp6, &zerogrp6);
	}

	/* Only start timers if not called manually. */
	if ((ev & EV_TIMEOUT) == EV_TIMEOUT) {
		evtimer_add(qtimerev, &qtv);
		mrt_querytimeradd();
	}
}

void
intf_setup(void)
{
	struct intf_data		*id;

	SLIST_FOREACH(id, &iflist, id_entry) {
		/* Disable IPv4 multicast if disabled globally. */
		if (ic.ic_ipv4 == 0)
			id->id_mv4 = 0;
		/* Disable IPv6 multicast if disabled globally. */
		if (ic.ic_ipv6 == 0)
			id->id_mv6 = 0;

		if (id->id_dir == IDIR_DISABLE)
			continue;

		/* Register all enabled interfaces. */
		vif_register(id);

		if (id->id_dir != IDIR_DOWNSTREAM)
			continue;

		/* Only join downstream interfaces. */
		mcast_join(id, NULL);
	}
}
