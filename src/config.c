#include "config.h"

/*
 * configuration format similar to login.defs
 * KEY  "value" # comment
 */

/* skip spaces at this position, moving forward or back */
/* XXX be sure you know what you are doing with n != 1 */
char *skipspaces (char *s, int n) {
	while (*s && isspace (*s))
		s += n;
	return s;
}

static int cfgcmp (const void *name, const void *c) {
	return strcmp ((const char *)name, ((const struct conf *)c)->name);
}

#define PNSZ(s) &(s), ARRAYN (s), sizeof (*(s))
/* do the actual search */
static struct conf *cget (const char *name, struct conf **c, size_t num, size_t sz) {
	return (struct conf *)bsearch (name, c, num, sz, cfgcmp);
}

/* this should be done better */
int parseconfig (const char *file, struct conf **config, size_t num, size_t sz) {
	struct conf *cfg;
	ssize_t r;
	size_t n = 0;
	char *line = NULL;
	FILE *f = fopen (file, "r");
	if (!f)
		return 0;

	while ((r = getline (&line, &n, f)) != -1) {
		char *p, *c;
		size_t l;

		/* this should not happen */
		if (r == 0)
			continue;

		/* skip leading spaces */
		p = skipspaces (line, 1);

		/* find terminal delimiter: comment, eol, or eof */
		if ((c = strpbrk (p, "\n#")))
			r = c - p;
		else
			/* missing \n at eof */
			r -= p - line;

		/* no content */
		if (r == 0)
			continue;

		/* replace terminal delimiter with nul */
		if (c)
			*c = '\0';

		/* find delimiter after key: whitespace */
		c = strpbrk (p, "\t\v\f ");
		if (!c)
			continue;

		/* calculate key length */
		/* it should not be possible for the first character to be
		whitespace after skipping leading whitespaces */
		assert (c != p);
		l = c - p;

		/* also replace delimiter with nul */
		*c = '\0';

		/* get the variable corresponding to the key */
		cfg = cget (p, config, num, sz);
		if (!cfg)
			/* warning would be noisy with login.defs */
			continue;

		/* find start of value */
		p += l + 1;
		r -= l + 1;
		c = skipspaces (c + 1, 1);
		if (!*c)
			continue;

		/* quoted value */
		if (*c == '"') {
			char *e = strchr (++c, '"');
			/* end of quote is eol */
			if (e)
				*e = '\0';
		}

		if (cfg->type == T_INT)
			cfg->value.num = atoi (c);
		else if (cfg->type == T_STR)
			cfg->value.str = strdup (c);
	}
	fclose (f);
	free (line);
	return 1;
}

static struct conf configuration[] = {
	{ .name = "EVT_EXT", .type = T_STR, .value.str = EVT_EXT },
	{ .name = "GROUP", .type = T_STR, .value.str = GROUP },
	{ .name = "LOGIN_DEFS", .type = T_STR, .value.str = LOGIN_DEFS },
	/*{ .name = "MAIL_HEADER", .type = T_STR, .value.str = "This is to inform you about %n" },
	{ .name = "MAIL_SUBJECT", .type = T_STR, .value.str = "runevent: %n" }, */
	{ .name = "MAILER", .type = T_STR, .value.str = MAILER },
	{ .name = "MAX_PROCS", .type = T_INT, .value.num = 4 },
	{ .name = "NICE", .type = T_INT, .value.num = 0 },
	{ .name = "PROC_RUN_TIME", .type = T_INT, .value.num = 120 },
	{ .name = "PROC_SIG_TIME", .type = T_INT, .value.num = 5 },
	/*{ .name = "RLIMIT", .type = T_INT, .value.num = 0 },*/
	{ .name = "SYS_DIR", .type = T_STR, .value.str = SYS_DIR },
	{ .name = "SYS_EVT_DIR", .type = T_STR, .value.str = SYS_EVT_DIR },
	{ .name = "UID_MAX_KEY", .type = T_STR, .value.str = UID_MAX_KEY },
	{ .name = "UID_MIN_KEY", .type = T_STR, .value.str = UID_MIN_KEY },
	{ .name = "USER_EVT_DIR", .type = T_STR, .value.str = USER_EVT_DIR },
	{ .name = "USER_NICE", .type = T_INT, .value.num = 0 },
	/*{ .name = "USER_RLIMIT", .type = T_INT, .value.num = 0 }*/
};

int readconfig (void) {
	return parseconfig (CONFIGFILE, PNSZ (configuration));
}

struct conf *cfgget (const char *name) {
	return cget (name, PNSZ (configuration));
}

int cfgvalue (const char *name) {
	struct conf *c = cfgget (name);
	return c ? c->value.num : 0;
}

char *cfgstr (const char *name) {
	struct conf *c = cfgget (name);
	return c ? c->value.str : NULL;
}

/* this does not really belong here */
static struct conf uidrange[] = {
	{ .name = "UID_MAX", .type = T_INT, .value.num = INT_MAX },
	{ .name = "UID_MIN", .type = T_INT, .value.num = INT_MIN }
};

static int getuidrange (void) {
	static char *defs = NULL;
	if (defs)
		return 1;

	defs = cfgstr ("LOGIN_DEFS");
	return parseconfig (defs, PNSZ (uidrange));
};

int uidmax (void) {
	struct conf *c;
	getuidrange ();
	c = cget ("UID_MAX", PNSZ (uidrange));
	return c->value.num;
}

int uidmin (void) {
	struct conf *c;
	getuidrange ();
	c = cget ("UID_MIN", PNSZ (uidrange));
	return c->value.num;
}

#ifndef NDEBUG
/* verify that this configuration array is sorted */
static void checkconfiguration (const struct conf *c, size_t n, size_t sz) {
	size_t i, f = 0;
	char *p = "\0";
	for (i = 0; i < n; p = c[i++].name) {
		if (strcmp (p, c[i].name) > 0) {
			DEBUG ("wrong order: '%s' > '%s'", p, c[i].name);
			f++;
		}
	}
	if (f)
		exit (EXIT_FAILURE);
}

void checkconfigs (void) {
	checkconfiguration (PNSZ (configuration));
	checkconfiguration (PNSZ (uidrange));
}
#endif
