# $OpenBSD:$

SRCS		 = mcast-proxy.c kroute.c log.c mrt.c parse.y util.c
PROG		 = mcast-proxy
MAN			 = mcast-proxy.8 mcast-proxy.conf.5

CFLAGS	  += -I${.CURDIR}
CFLAGS		+= -Wall -Wextra -Wshadow
CFLAGS		+= -Wmissing-prototypes -Wmissing-declarations
CFLAGS		+= -Wstrict-prototypes -Wpointer-arith -Wsign-compare
DPADD			 = ${LIBEVENT}
LDADD			 = -levent

.include <bsd.prog.mk>
