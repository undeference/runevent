/*
 * runevent - run system and user handlers in response to events
 * <https://github.com/undeference/runevent>
 * Copyright © M. Kristall
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */

#ifndef _RUNEVENT
#define _RUNEVENT
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>

#define ARRAYN(a) (sizeof (a) / sizeof (*(a)))

#ifndef NDEBUG
#define DEBUG(f,...) \
	fprintf (stderr, "%s:%d %s() " f "\n", \
		__FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define DEBUG(f,...)
#endif

extern int sysrun;
#define syslog(l,...) do { \
	if (sysrun) \
		syslog (l, __VA_ARGS__); \
	else { \
		FILE *fh = l > LOG_NOTICE ? stderr : stdout; \
		fprintf (fh, __VA_ARGS__); \
		fputc ('\n', fh); \
	} \
} while (0)

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(x) do { } while ((x) == -1 && errno == EINTR)
#endif
extern fd_set fdset;
extern int nfds;

#define SETFDS(fd) do { \
	size_t i; \
	for (i = 0; i < ARRAYN (fd); i++) { \
		if ((fd)[i] >= nfds) \
			nfds = (fd)[i] + 1; \
		FD_SET ((fd)[i], &fdset); \
	} \
} while (0)
#define CLRFDS(fd) do { \
	size_t i; \
	for (i = 0; i < ARRAYN (fd); i++) { \
		FD_CLR ((fd)[i], &fdset); \
		(fd)[i] = -1; \
	} \
	while (nfds > 0 && !FD_ISSET (nfds - 1, &fdset)) \
		nfds--; \
} while (0)

#define closefd(f) TEMP_FAILURE_RETRY (close (f))
#define dupfd(f,t) TEMP_FAILURE_RETRY (dup2 (f, t))

struct subproc *runevent (const struct passwd *pw, char * const *argv, char * const *env);
#endif
