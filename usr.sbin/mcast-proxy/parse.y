/*	$OpenBSD:$	*/

/*
 * Copyright (c) 2017 Rafael Zalamena <rzalamena@openbsd.org>
 * Copyright (c) 2015 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
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

%{
#include <arpa/inet.h>

#include <sys/limits.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "mcast-proxy.h"

struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
};
TAILQ_HEAD(files, file);

struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
TAILQ_HEAD(symhead, sym);

typedef struct {
	union {
		int64_t			 number;
		char			*string;
	} v;
	int lineno;
} YYSTYPE;

#define MAXPUSHBACK	128

static int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
static int		 kw_cmp(const void *, const void *);
static int		 lookup(char *);
static int		 lgetc(int);
static int		 lungetc(int);
static int		 findeol(void);
static int		 yylex(void);
static int		 check_file_secrecy(int, const char *);
static struct file	*pushfile(const char *, int);
static int		 popfile(void);
static int		 yyparse(void);
static int		 symset(const char *, const char *, int);
static char		*symget(const char *);

static struct file		*file, *topfile;
static struct files		 files = TAILQ_HEAD_INITIALIZER(files);
static struct symhead		 symhead = TAILQ_HEAD_INITIALIZER(symhead);
static int			 errors;

static unsigned char		*parsebuf;
static int			 parseindex;
static unsigned char		 pushback_buffer[MAXPUSHBACK];
static int			 pushback_index;

struct intf_data	*cid;

%}

%token IPV4 IPV6 INTERFACE DISABLE DOWNSTREAM SOURCE UPSTREAM THRESHOLD
%token INCLUDE YES NO
%token ERROR
%token <v.string>	STRING
%token <v.number>	NUMBER
%type  <v.number>	yesno
%type  <v.string>	string

%%

grammar	: /* empty */
	| grammar '\n'
	| grammar conf_opt '\n'
	| grammar include '\n'
	| grammar varset '\n'
	| grammar error '\n' { file->errors++; }
	;

conf_opt : INTERFACE STRING {
		cid = intf_lookupbyname($2);
		if (cid == NULL) {
			cid = id_new();
			if (cid == NULL)
				fatal("%s:%d: calloc",
				    file->name, yylval.lineno);
			if (strlcpy(cid->id_name, $2,
			    sizeof(cid->id_name)) >= sizeof(cid->id_name))
				fatalx("%s:%d: interface name too long",
				    file->name, yylval.lineno);
		}

		cid->id_mv4 = ic.ic_ipv4;
		cid->id_mv6 = ic.ic_ipv6;
	} intf_block
	| global_ip
	;

global_ip : IPV4 yesno { ic.ic_ipv4 = $2; }
	  | IPV6 yesno { ic.ic_ipv6 = $2; }
	  ;

intf_block : '{' optnl intf_opts '}'
	   | '{' optnl '}'
	   ;

intf_opts : intf_opt nl intf_opts
	  | intf_opt optnl
	  ;

intf_opt : THRESHOLD NUMBER {
		if ($2 < 1 || $2 > 255)
			fatalx("%s:%d: invalid threshold value: %llu",
			    file->name, yylval.lineno, $2);

		cid->id_ttl = $2;
	 }
	 | SOURCE STRING {
		struct intf_addr	*ia;
		char			*prefixp;
		const char		*errp;

		prefixp = strchr($2, '/');
		if (prefixp == NULL)
			fatalx("%s:%d: failed to find prefix",
			    file->name, yylval.lineno);

		*prefixp = 0;
		prefixp++;
		if (*prefixp == 0)
			fatalx("%s:%d: empty prefix",
			    file->name, yylval.lineno);

		ia = calloc(1, sizeof(*ia));
		if (ia == NULL)
			fatal("%s:%d: calloc",
			    file->name, yylval.lineno);

		if (inet_pton(AF_INET, $2, &ia->ia_addr) != 1) {
			if (inet_pton(AF_INET6, $2, &ia->ia_addr) != 1) {
				fatalx("%s:%d: invalid address '%s'",
				    file->name, yylval.lineno, $2);
			} else
				ia->ia_af = AF_INET6;
		} else
			ia->ia_af = AF_INET;

		ia->ia_prefixlen = strtonum(prefixp, 0, 128, &errp);
		if (errp != NULL)
			fatalx("%s:%d: invalid prefix length: %s",
			    file->name, yylval.lineno, errp);
		if (ia->ia_af == AF_INET && ia->ia_prefixlen > 32)
			fatalx("%s:%d: invalid prefix length",
			    file->name, yylval.lineno);
		else if (ia->ia_af == AF_INET6 && ia->ia_prefixlen > 128)
			fatalx("%s:%d: invalid prefix length",
			    file->name, yylval.lineno);

		SLIST_INSERT_HEAD(&cid->id_altnetlist, ia, ia_entry);
	}
	| UPSTREAM {
		if (upstreamif != NULL)
			fatalx("%s:%d: it is not possible to have "
			    "multiple upstream interfaces.",
			    file->name, yylval.lineno);

		upstreamif = cid;
		cid->id_dir = IDIR_UPSTREAM;
	}
	| DOWNSTREAM { cid->id_dir = IDIR_DOWNSTREAM; }
	| DISABLE { cid->id_dir = IDIR_DISABLE; }
	| IPV4 yesno { cid->id_mv4 = $2; }
	| IPV6 yesno { cid->id_mv6 = $2; }
	;

include : INCLUDE STRING {
		struct file	*nfile;

		if ((nfile = pushfile($2, 1)) == NULL) {
			yyerror("failed to include file %s", $2);
			free($2);
			YYERROR;
		}
		free($2);

		file = nfile;
		lungetc('\n');
	}
	;

varset : STRING '=' string {
		const char *s = $1;
		while (*s++) {
			if (isspace((unsigned char)*s)) {
				yyerror("macro name cannot contain "
				    "whitespace");
				YYERROR;
			}
		}
		if (symset($1, $3, 0) == -1)
			fatal("cannot store variable");
		free($1);
		free($3);
	}
	;

string : string STRING	{
		if (asprintf(&$$, "%s %s", $1, $2) == -1) {
			free($1);
			free($2);
			yyerror("string: asprintf");
			YYERROR;
		}
		free($1);
		free($2);
	}
	| STRING
	;

optnl	: '\n' optnl
	|
	;

nl	: '\n' optnl
	;

yesno	: YES	{ $$ = 1; }
	| NO	{ $$ = 0; }
	;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

static int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

static int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

static int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{"disabled",			DISABLE},
		{"downstream",			DOWNSTREAM},
		{"include",			INCLUDE},
		{"interface",			INTERFACE},
		{"ipv4",			IPV4},
		{"ipv6",			IPV6},
		{"no",				NO},
		{"source",			SOURCE},
		{"threshold",			THRESHOLD},
		{"upstream",			UPSTREAM},
		{"yes",				YES},
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

static int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

static int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

static int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

static int
yylex(void)
{
	unsigned char	 buf[8096];
	unsigned char	*p, *val;
	int		 quotec, next, c;
	int		 token;

 top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

static int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

static struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("calloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("strdup");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

static int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

static int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(const char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		errx(1, "cmdline_symset: malloc");

	strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

static char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

int
parse_config(const char *filename)
{
	if ((file = pushfile(filename, 0)) == NULL)
		return -1;

	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();
	if (errors)
		return -1;

	return 0;
}
