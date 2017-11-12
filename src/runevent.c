/*
 * runevent - run system and user handlers in response to events
 * <https://github.com/undeference/runevent>
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

#include "runevent.h"
#include "subproc.h"
#include "config.h"
#include <bheap.h>

int sysrun = 0;
fd_set fdset;
int nfds = 0;
char *evt;

/* SIGCHLD */
/* check if this is the subprocess that exited (CHLD) */
int spexited (const void *arg1, void *arg2) {
	struct subproc *proc = *(struct subproc **)arg1;
	pid_t *pid = arg2;

	/* the subprocess exited */
	if (proc->pid == *pid) {
		/* just mark it because messing with the bheap is unsafe here */
		proc->status = SPEXITED;
		return 1;
	}

	/* the mailer exited */
	if (proc->mail.pid == *pid) {
		closefd (proc->mail.fd[0]);
		proc->mail.pid = 0;
		proc->mail.fd[0] = -1;
		return 1;
	}

	/* this is not a match */
	return 0;
}

static int reap = 0;
static bheap_t *heap;
void chld (int signum, siginfo_t *sinfo, void *unused) {
	/* this should only be ours but if not, still need to reap */
	int status, code;
	int sen = errno;
	/* actually don't care if it was stopped or the like */
	pid_t pid = sinfo->si_pid;
	DEBUG ("CHLD pid %d", pid);
	if (waitpid (pid, &status, 0) == -1) {
		DEBUG ("waitpid failed: %s", strerror (errno));
		goto done;
	}

	reap = 1;
	/* report if it was not successful */
	if (WIFEXITED (status)) {
		if ((code = WEXITSTATUS (status)) != EXIT_SUCCESS)
			syslog (LOG_WARNING, "%d exited with status %d",
				pid, code);
	} else if (WIFSIGNALED (status)) {
		code = WTERMSIG (status);
		syslog (LOG_WARNING, "%d was terminated by signal %d",
			pid, code);
	}

	/* it is not safe to mess with the bheap here */
	if (heapsearch (heap, NULL, 0, spexited, &pid) == -1)
		/* this is not really an error */
		syslog (LOG_WARNING, "got unexpected CHLD signal for %d", pid);

	done:
	errno = sen;
}

int newlen (size_t *len, const size_t min) {
	if (*len >= min)
		return 0;
	if (!*len)
		*len = 64;
	do {
		*len *= 2;
	} while (*len < min);
	return 1;
}

char *evtpath (const struct passwd *pw) {
	static size_t size = 0;
	static char *path = NULL;
	ssize_t i = 0;
	/* path components:
	0         1 2      3      4   5
	SYSEVTDIR / evt    EVTEXT
	home      / EVTDIR /      evt EVTEXT */
#define MAXEVTCOMPS 6
	char *paths[MAXEVTCOMPS];
	size_t lens[MAXEVTCOMPS], len = 0;
#undef MAXEVTCOMPS
/* maxlen += (lens[i] = strlen ((paths[i] = (comp)))), i++; */
#define EVTCOMP(comp) do { \
	paths[i] = (comp); \
	lens[i] = strlen (paths[i]); \
	len += lens[i]; \
	i++; \
} while (0)
	if (pw) {
		EVTCOMP (pw->pw_dir);
		EVTCOMP ("/");
		EVTCOMP (cfgstr ("USER_EVT_DIR"));
		EVTCOMP ("/");
		EVTCOMP (evt);
		EVTCOMP (cfgstr ("EVT_EXT"));
	} else {
		EVTCOMP (cfgstr ("SYS_EVT_DIR"));
		EVTCOMP ("/");
		EVTCOMP (evt);
		EVTCOMP (cfgstr ("EVT_EXT"));
	}
#undef EVTCOMP
	if (newlen (&size, len + 1)) {
		path = path ? realloc (path, size) : malloc (size);
		if (!path) {
			syslog (LOG_CRIT, "alloc of %zd failed: %s",
				size, strerror (errno));
			exit (EXIT_FAILURE);
		}
	}
	path[len] = '\0';
	for (i--; len > 0 && i >= 0; len -= lens[i], i--)
		memcpy (path + len - lens[i], paths[i], lens[i]);
	return path;
}

struct subproc *runevent (const struct passwd *pw, char * const *argv, char * const *env) {
	struct subproc *proc = calloc (1, sizeof (struct subproc));
	proc->mail.fd[0] = -1;
	proc->status = SPRUN;

	if (pw) {
		proc->uid = pw->pw_uid;
		proc->gid = pw->pw_gid;
	}

	/* actually run it */
	proc->pid = open3 (NULL, &proc->fd[0], &proc->fd[1], pw, argv, env);
	if (proc->pid == -1)
		goto fail;

	DEBUG ("open3 '%s' pid %d with stdout piped to %d and stderr to %d", argv[0], proc->pid, proc->fd[0], proc->fd[1]);
	syslog (LOG_INFO, "run %s[%d] for %s", argv[0], proc->pid,
		pw ? pw->pw_name : "system");

	/* let use select on stdout and stderr */
	SETFDS (proc->fd);

	/* set process timeout */
	clock_gettime (CLOCK_MONOTONIC, &proc->time);
	proc->time.tv_sec += cfgvalue ("PROC_RUN_TIME");

	/* it should have its own copy of its name */
	proc->path = strdup (argv[0]);

	/* add it to the bheap */
	heapup (heap, &proc);
	return proc;

	fail:
	free (proc);
	return NULL;
}

/* should this be run? */
static struct subproc *runif (const struct passwd *pw, char **argv, char * const *env) {
	struct stat f;

	argv[0] = evtpath (pw);

	/* is there a handler for this event? */
	if (stat (argv[0], &f) != 0)
		return NULL;

	/* is it a regular file? */
	if (!S_ISREG (f.st_mode))
		return NULL;

	/* be more lenient for user-only runs */
	if (sysrun) {
		/* check ownership */
		if (f.st_uid != (pw ? pw->pw_uid : 0)) {
			syslog (LOG_ERR, "'%s' is not owned by %s",
				argv[0], pw ? pw->pw_name : "root");
			return NULL;
		}

		/* check permissions */
		if (f.st_mode & (S_ISUID | S_IWGRP | S_IWOTH)) {
			syslog (LOG_ERR, "'%s' must not be group/user-writable "
				"or setuid", argv[0]);
			return NULL;
		}
	}

	/* is it allowed to be run? */
	if (!(f.st_mode & S_IXUSR)) {
		syslog (LOG_ERR, "'%s' is not exutable", argv[0]);
		return NULL;
	}

	return runevent (pw, argv, env);
}

/* is this user allowed to have event handlers? */
int userok (const struct passwd *pw) {
	struct group *gr;
	char **mem;
	char *grnam;

	/* is this user in an allowable uid range? */
	if (pw->pw_uid < uidmin () || pw->pw_uid > uidmax ())
		return 0;

	/* see if they are in an allowed group */
	grnam = cfgstr ("GROUP");
	/* no group specified, so it's ok */
	if (!*grnam)
		return 1;

	if (!(gr = getgrnam (grnam))) {
		syslog (LOG_WARNING, "no such group '%s': ignoring", grnam);
		goto success;
	}

	DEBUG ("checking if %s is a member of %s", pw->pw_name, grnam);

	if (pw->pw_gid == gr->gr_gid)
		goto success;

	for (mem = gr->gr_mem; *mem; mem++) {
		if (strcmp (pw->pw_name, *mem) == 0)
			goto success;
	}

	endgrent ();
	return 0;
	success:
	endgrent ();
	return 1;
}

struct spout {
	int num;
	fd_set fdset;
};
int spoutput (const void *arg1, void *arg2) {
	struct subproc *proc = *(struct subproc **)arg1;
	struct spout *output = arg2;
	readfd2 (proc, &output->fdset, &output->num);
	/* this is run by heapsearch(), so lie that this was not a match */
	return 0;
}

int spdelall (const void *arg1, void *arg2) {
	struct subproc *proc = *(struct subproc **)arg1;
	cleanchild (proc);
	free (proc);
	return 1;
}

/* remove subprocs from the bheap that have exited */
int spdel (const void *arg1, void *arg2) {
	struct subproc *proc = *(struct subproc **)arg1;
	if (proc->status != SPEXITED)
		return 0;
	cleanchild (proc);
	free (proc);
	return 1;
}

void tsdiff (struct timespec *dest, struct timespec *a, struct timespec *b) {
	long nsec = a->tv_nsec - b->tv_nsec;
	dest->tv_sec = a->tv_sec - b->tv_sec;
	if (nsec < 0) {
		nsec += 1000000000L;
		dest->tv_sec--;
	}
	dest->tv_nsec = nsec;
}

int spcmp (const void *arg1, const void *arg2) {
	const struct subproc *a = *(const struct subproc **)arg1,
		*b = *(const struct subproc **)arg2;
	return a->time.tv_sec == b->time.tv_sec ?
		a->time.tv_nsec - b->time.tv_nsec :
		a->time.tv_sec - b->time.tv_sec;
}

/*
runevent evtname envname=value…
*/
int main (int argc, char **argv) {
	struct sigaction sa;
	struct passwd *pw = NULL;
	struct timespec now;
	struct subproc *proc;
	int i = 1, j, done = 0;
	int maxprocs, procsigtime;
	char *args[2], *env[argc - 1];
	uid_t uid = getuid ();

	if (argc <= i) {
		syslog (LOG_CRIT, "no arguments specified");
		goto fail;
	}

	/* allow -u user for root */
	if (argv[i][0] == '-' && argv[i][1] == 'u') {
		char *name;
		if (uid != 0) {
			syslog (LOG_ERR, "-u is only valid if you are root");
			goto fail;
		}

		if (argv[i][2])
			/* -uuser */
			name = &argv[i][2];
		else if (++i >= argc) {
			syslog (LOG_CRIT, "user expected for -u option");
			goto fail;
		} else
			/* -u user */
			name = argv[i];

		errno = 0;
		/* check if this is a valid user */
		if (!(pw = getpwnam (name))) {
			syslog (LOG_CRIT, "getpwnam(\"%s\"): %s", name,
				errno ? strerror (errno) : "no such user");
			goto fail;
		}

		/* start with the event */
		i++;

		/* XXX can this be done elsewhere? */
		/* drop privileges */
		uid = pw->pw_uid;
		if (!su (pw))
			/* no need to warn here since su() is noisy */
			goto fail;
		setupenv (pw, NULL);
		closefrom (3);
	/* otherwise, if it's run by root, it's a system run */
	} else if (uid == 0)
		sysrun = 1;
	/* else, this is a user-specific run */
	/*
	else
		syslog (LOG_WARNING,
			"(%s must be run as root to do a system-wide run)",
			argv[0]);
	*/

	/* Make syslog() do what it should for a system run */
	if (sysrun) {
		const char *dir = cfgstr ("SYS_DIR");
		openlog ("runevent", 0, LOG_DAEMON);
		if (dir && chdir (dir) != 0) {
			syslog (LOG_ERR, "chdir(\"%s\"): %s",
				dir, strerror (errno));
			goto fail;
		}
	}

	/* too few arguments */
	if (argc < i + 1) {
		syslog (LOG_CRIT, "%s: no event specified", argv[0]);
		goto fail;
	}

	/* verify correct orders */
#ifndef NDEBUG
	checkconfigs ();
#endif

	/* get configuration for system run */
	if (sysrun)
		readconfig ();

	/* set up argv and env for subprocs */
	evt = argv[i];
	/* argv[0] will be set below */
	args[1] = NULL;
	for (j = 0; j < argc - i; j++)
		env[j] = argv[j + i];
	env[j] = NULL;

	FD_ZERO (&fdset);

	/* do some configuration sanity checking */
	maxprocs = cfgvalue ("MAX_PROCS");
	if (maxprocs < 1) {
		syslog (LOG_WARNING, "MAX_PROCS (%d) is less than 1", maxprocs);
		maxprocs = 1;
	}

	procsigtime = cfgvalue ("PROC_SIG_TIME");
	/* maybe this should mean "don't bother"? */
	if (procsigtime < 1) {
		syslog (LOG_WARNING, "PROC_SIG_TIME (%d) is less than 1",
			procsigtime);
		procsigtime = 1;
	}

	/* set up CHLD handler */
	sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
	sa.sa_sigaction = chld;
	sigemptyset (&sa.sa_mask);
	if (sigaction (SIGCHLD, &sa, NULL) == -1) {
		syslog (LOG_CRIT, "register CHLD handler: %s",
			strerror (errno));
		goto fail;
	}

	/* set up priority queue */
	heap = heapalloc (-1, maxprocs, sizeof (struct subproc *), spcmp);
	if (!heap) {
		syslog (LOG_CRIT, "could not allocate heap");
		goto fail;
	}

	/* this is not a system run so skip some of the work */
	if (!sysrun) {
		errno = 0;
		if (!(pw = getpwuid (uid))) {
			syslog (LOG_CRIT, "getpwuid(%d): %s", uid,
				errno ? strerror (errno) : "no such user");
			goto fail;
		}
		/* don't try to run more handlers */
		done = 1;
	}

	/* try running system or user event handler */
	proc = runif (pw, args, env);

	/* main loop */
	while (1) {
		clock_gettime (CLOCK_MONOTONIC, &now);
		/* can't run any more handlers (for now) */
		if (done || heapcount (heap) == maxprocs) {
			struct timespec timeout;
			struct spout output;
			/* get the first subproc from the bheap */
			if (!heappeek (heap, &proc))
				break;

			output.fdset = fdset;
			/* subproc has been running too long */
			tsdiff (&timeout, &proc->time, &now);
			if (timeout.tv_sec < 0) {
				if (proc->status == SPRUN) {
					DEBUG ("kill -TERM %d", proc->pid);
					kill (proc->pid, SIGTERM);
					/* reposition subproc in heap */
					heapdown (heap, NULL);
					proc->time = now;
					proc->time.tv_sec += procsigtime;
					/* subproc has been signaled once */
					proc->status = SPSIG;
					heapup (heap, &proc);
				} else if (proc->status == SPSIG) {
					DEBUG ("kill -KILL %d", proc->pid);
					kill (proc->pid, SIGKILL);
					/* don't waitpid() here */
				}
				/* timeout is negative, so don't select() */
				continue;
			}

			/* do the actual select() */
			TEMP_FAILURE_RETRY (output.num = pselect (nfds,
				&output.fdset, NULL, NULL /* check too? */,
				&timeout, NULL));
			if (output.num < 0) {
				/* can this really be that bad? */
				DEBUG ("select(): %s", strerror (errno));
				continue;
			}

			/* if a subproc printed something, handle that */
			if (output.num > 0)
				heapsearch (heap, NULL, 0, spoutput, &output);

			/* clear slots from exited subprocs */
			if (reap) {
				heapdelete (heap, spdel, NULL);
				reap = 0;
			}
			continue;
		}
		/* execution only reaches this point for system runs */

		/* check if users are allowed to run handlers */
		if (!(pw = getpwent ()))
			done = 1;
		else if (userok (pw))
			proc = runif (pw, args, env);
	}
	endpwent ();
	return EXIT_SUCCESS;

	fail:
	/* this should probably handle currently running subprocs better */
	endpwent ();
	if (heap) {
		heapdelete (heap, spdelall, NULL);
		heapfree (heap);
	}
	closelog ();
	return EXIT_FAILURE;
}