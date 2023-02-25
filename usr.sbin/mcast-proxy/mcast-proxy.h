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

#ifndef MCAST_PROXY_H
#define MCAST_PROXY_H

#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <net/if.h>

#include <event.h>

#include "log.h"

#define MCAST_PROXY_USER		"_mcastproxy"

/* RFC 2236 section 8: value definitions. */
#define IGMP_QUERY_INTERVAL		125 /* 125 seconds. */
#define IGMP_RESPONSE_INTERVAL		10 /* 10 seconds. */
#define IGMP_ROBUSTNESS_DEFVALUE	2
#define IGMP_STARTUP_QUERY_INTERVAL (IGMP_QUERY_INTERVAL * 0.25)
/*
 * RFC 2236 Section 8.4: Group membership interval.
 * Group membership interval is composed by the following formula:
 * (Robustness * Query_Interval) + Query_Response_Interval.
 */
#define IGMP_GROUP_MEMBERSHIP_INTERVAL ((IGMP_ROBUSTNESS_DEFVALUE * \
	IGMP_QUERY_INTERVAL) + IGMP_RESPONSE_INTERVAL)

/* Signalize invalid virtual/multicast interface index. */
#define INVALID_VINDEX ((uint16_t)-1)

/* Interface direction configuration values. */
enum intf_direction {
	IDIR_DISABLE = 0,
	IDIR_DOWNSTREAM,
	IDIR_UPSTREAM,
};

enum mr_version {
	MV_UNKNOWN,
	MV_IGMPV1,
	MV_IGMPV2, /* or MLDv1. */
	MV_IGMPV3, /* or MLDv2. */
};

union uaddr {
	struct in_addr		v4;
	struct in6_addr		v6;
};

struct intf_addr {
	SLIST_ENTRY(intf_addr)	 ia_entry;
	int			 ia_af;
	union uaddr		 ia_addr;
	uint8_t			 ia_prefixlen;
};
SLIST_HEAD(ialist, intf_addr);

struct intf_data {
	SLIST_ENTRY(intf_data)		 id_entry;

	/* Interface status. */
	int				 id_enabled;
	/* Interface name. */
	char				 id_name[IFNAMSIZ];
	/* Interface index. */
	unsigned int			 id_index;
	/* Interface rdomain. */
	unsigned int			 id_rdomain;
	/* Interface flags. */
	unsigned int			 id_flags;
	/* Interface IPv4 list. */
	struct ialist			 id_ialist;
	/* Interface alternative networks. */
	struct ialist			 id_altnetlist;

	/* Multicast configurations. */

	/* Virtual interface index. */
	uint16_t			 id_vindex;
	/* Virtual IPv6 interface index. */
	uint16_t			 id_vindex6;
	/* Interface direction configuration. */
	enum intf_direction		 id_dir;
	/* Acceptable TTL threshold. */
	uint8_t				 id_ttl;
	/* Use IPv4 multicast. */
	int				 id_mv4;
	/* Use IPv6 multicast. */
	int				 id_mv6;
};
SLIST_HEAD(iflist, intf_data);

struct multicast_origin {
	LIST_ENTRY(multicast_origin) mo_entry;
	int			 mo_alive;
	int			 mo_af;
	struct intf_data	*mo_id;
	union uaddr		 mo_addr;
};
LIST_HEAD(molist, multicast_origin);

struct igmpproxy_conf {
	int			 ic_ipv4;
	int			 ic_ipv6;
};

/* igmp-proxy.c */
extern struct intf_data		*upstreamif;
extern struct iflist		 iflist;
extern int			 igmpsd;
extern int			 mldsd;
extern struct igmpproxy_conf	 ic;

/* kroute.c */
void assert_mcastforward(void);
int intf_init(void);
int igmp_setif(struct intf_data *);
int vif_register(struct intf_data *);
int vif_unregister(struct intf_data *);
int vif4_register(struct intf_data *);
int vif4_unregister(struct intf_data *);
int vif6_register(struct intf_data *);
int vif6_unregister(struct intf_data *);
void intf_dispatch(int, short, void *);
void intf_load(void);
int open_igmp_socket(void);
int close_igmp_socket(int);
int open_mld_socket(void);
int close_mld_socket(int);
int mcast_join(struct intf_data *, struct sockaddr_storage *);
int mcast_leave(struct intf_data *, struct sockaddr_storage *);
int mcast4_join(struct intf_data *, struct in_addr *);
int mcast4_leave(struct intf_data *, struct in_addr *);
int mcast6_join(struct intf_data *, struct in6_addr *);
int mcast6_leave(struct intf_data *, struct in6_addr *);
int mcast_addroute(unsigned short, union uaddr *, union uaddr *,
    struct molist *);
int mcast_addroute6(unsigned short, union uaddr *, union uaddr *,
    struct molist *);
int mcast_delroute(unsigned short, union uaddr *, union uaddr *);
int mcast_delroute6(unsigned short, union uaddr *, union uaddr *);

/* util.c */
const char *addrtostr(struct sockaddr_storage *);
const char *addr4tostr(struct in_addr *);
const char *addr6tostr(struct in6_addr *);
int id_matchaddr4(struct intf_data *, uint32_t);
int id_matchaddr6(struct intf_data *, struct in6_addr *);
uint16_t checksum(uint8_t *, uint16_t, uint32_t);
uint16_t wrapsum(uint16_t);
struct intf_data *id_insert(unsigned short);
struct intf_data *id_new(void);
void id_free(struct intf_data *);
void ia_inserttail(struct ialist *, struct intf_addr *);
struct intf_data *intf_lookupbyname(const char *);
struct intf_data *intf_lookupbyaddr4(uint32_t);
struct intf_data *intf_lookupbyaddr6(struct in6_addr *);
struct intf_data *intf_lookupbyindex(unsigned short);
struct intf_addr *intf_primaryv4(struct intf_data *);
struct intf_addr *intf_ipv6linklayer(struct intf_data *);
uint8_t mask2prefixlen(in_addr_t);
uint8_t mask2prefixlen6(struct sockaddr_in6 *);
in_addr_t prefixlen2mask(uint8_t);
void applymask(int, union uaddr *, const union uaddr *, int);

/* mrt.c */
void mrt_querytimeradd(void);
struct multicast_route *mrt_insert4(enum mr_version, struct intf_data *,
    struct in_addr *, struct in_addr *);
struct multicast_route *mrt_insert6(enum mr_version, struct intf_data *,
    struct in6_addr *, struct in6_addr *);
void mrt_remove4(struct intf_data *, struct in_addr *, struct in_addr *);
void mrt_remove6(struct intf_data *, struct in6_addr *, struct in6_addr *);
void mrt_cleanup(void);

/* parse.y */
int cmdline_symset(const char *);
int parse_config(const char *);

/* Helpers */
static inline struct sockaddr_in *
sstosin(struct sockaddr_storage *ss)
{
	return (struct sockaddr_in *)ss;
}

static inline struct sockaddr_in6 *
sstosin6(struct sockaddr_storage *ss)
{
	return (struct sockaddr_in6 *)ss;
}

#endif /* MCAST_PROXY_H */
