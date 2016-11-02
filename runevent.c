#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>

/* specify -I or -L or whatever it is */
#include <bheap.h>

#ifndef LOGINDEFS
#define LOGINDEFS "/etc/login.defs"
#endif

#define LOGIN_UID_MIN "UID_MIN"
#define LOGIN_UID_MAX "UID_MAX"
static uid_t uidmin = (uid_t)INT_MIN, uidmax = (uid_t)INT_MAX;

#define USEROK(u) ((u)->pw_uid >= uidmin && (u)->pw_uid <= uidmax)

/* chdir here for system handlers */
#ifndef SYSDIR
#define SYSDIR "/"
#endif

/* path to system handler directory */
#ifndef SYSEVTDIR
#define SYSEVTDIR "/etc/events.d"
#endif

/* name of directory containing users' handlers */
#ifndef EVTDIR
#define EVTDIR "events.d"
#endif

/* these should maybe be in a config file (use login.defs format) */
/* event handlers end with this */
#ifndef EVTEXT
#define EVTEXT ".handler"
#endif

/* maximum number of handlers (for the same event) to run simultaneously */
#ifndef MAXPROCS
#define MAXPROCS 4
#endif
#if MAXPROCS < 1
#error "MAXPROCS must be at least 1"
#endif

/* how long a handler is allowed to run */
#ifndef PROCRUNTIME
#define PROCRUNTIME 120
#endif

/* maximum time to wait for a signalled handler to terminate */
#ifndef PROCSIGTIME
#define PROCSIGTIME 5
#endif

#ifndef MAILER
#define MAILER "/usr/bin/mail"
#endif

char *skipspaces (char *s, int n) {
	while (*s && isspace (*s))
		s += n;
	return s;
}

int getuidrange (void) {
	ssize_t r;
	size_t n = 0;
	char *line = NULL;
	FILE *defs = fopen (LOGINDEFS, "r");
	if (!defs)
		return -1;
	while ((r = getline (&line, &n, defs)) != -1) {
		char *p, *c;
		size_t l;
		uid_t *bound;
		if (r == 0)
			continue;
		p = skipspaces (line, 1);
		if ((c = strpbrk (p, "\n#")))
			r = c - p;
		else
			r -= p - line;
		/* find whitespace */
		if (!(c = strpbrk (p, "\t\v\f ")))
			continue;
		c++;
		if ((l = c - p) == 0)
			continue;
		if (strncmp (p, LOGIN_UID_MIN, l) == 0)
			bound = &uidmin;
		else if (strncmp (p, LOGIN_UID_MAX, l) == 0)
			bound = &uidmax;
		else
			continue;
		/* assume it's a real number */
		c = skipspaces (c, 1);
		*bound = (uid_t)atol (c);
	}
	fclose (defs);
	free (line);
	return 0;
}

void closefd (int fd) {
	int r;
	do {
		r = close (fd);
	} while (r == -1 && errno == EINTR);
}

void dupfd (int from, int to) {
	int r;
	do {
		r = dup2 (from, to);
	} while (r == -1 && errno == EINTR);
}

void closefrom (int min) {
	struct dirent *f;
	DIR *d = opendir ("/dev/fd");
	int fd;
	/* XXX complain */
	if (!d)
		return;
	while ((f = readdir (d))) {
		if (!isdigit (f->d_name[0]))
			continue;

		fd = atoi (f->d_name);
		if (fd >= min)
			closefd (fd);
	}
	closedir (d);
}

/* keep track of everything we need to keep track of for subprocs */
struct subproc {
	pid_t pid;
	uid_t uid;
	gid_t gid;
	/* readers for stdout and stderr */
	int outfd, errfd;
	/*
	 * if status == SPRUN then time is when the program started
	 * if status == SPSIG then time is when the program was signaled
	 */
	enum { SPRUN, SPSIG } status;
	/* clock_gettime(CLOCK_MONOTONIC) */
	struct timespec time;
};

static char *evt;
static fd_set readfds, errorfds;
static int nfds = 0;
static bheap_t *heap;

#define SETFDS(r,e) do { \
	if (r >= nfds) nfds = r + 1; \
	if (e >= nfds) nfds = e + 1; \
	FD_SET (r, &readfds); \
	FD_SET (e, &errorfds); \
} while (0)
/* doesn't adjust nfds (yet?) */
#define CLRFDS(r,e) do { \
	FD_CLR (r, &readfds); \
	FD_CLR (e, &errorfds); \
} while (0)

int spcmp (const void *arg1, const void *arg2) {
	const struct subproc *a = arg1, *b = arg2;
	return a->time.tv_sec == b->time.tv_sec ?
		a->time.tv_nsec - b->time.tv_nsec :
		a->time.tv_sec - b->time.tv_sec;
}

/*
 * Do nothing if there is no event handler
 * Drop privileges
 * pipe() for child stdout and stderr
 * if (fork())
 *	close writers
 *	register
 * else
 *	close readers
 *	close all other fds other than stdout, stderr
 *	clean environment
 *	ulimit
 *	execve()
 */
struct subproc *runevent (const struct passwd *pw, char * const *argv, char * const *env) {
	struct subproc *proc = calloc (1, sizeof (struct subproc));
	int out[2], err[2];
	proc->status = SPRUN;
	if (pw) {
		proc->uid = pw->pw_uid;
		proc->gid = pw->pw_gid;
	}
	/* set up pipes for stdout, stderr */
	if (pipe (out) != 0 || pipe (err) != 0)
		goto fail;
	proc->outfd = out[0];
	proc->errfd = err[0];
	/* now do the fork */
	proc->pid = fork ();
	/* XXX */
	if (proc->pid == -1)
		goto fail;
	if (!proc->pid) {
		/* child */
		char path[128];
		/*
		struct rlimit mem;
		mem.rlim_cur = mem.rlim_max = 128 << 20;
		setrlimit (RLIMIT_RSS, &mem);
		*/
		/* chdir() to user's home (or / for system) */
		if (chdir (pw ? pw->pw_dir : SYSDIR) != 0)
			exit (EXIT_FAILURE);
		/* drop privileges */
		if (setgid (proc->gid) != 0 || setuid (proc->uid) != 0)
			exit (EXIT_FAILURE);
		/* may need to know about root */
		if (!pw)
			pw = getpwuid (proc->uid);
		/* we are the child, so close the readers */
		closefd (out[0]);
		closefd (err[0]);
		/* dup to stdout and stderr */
		dupfd (out[1], 1);
		dupfd (err[1], 2);
		/* and close all other descriptors */
		closefrom (3);
		/* set up env */
		if (clearenv () != 0)
			exit (EXIT_FAILURE);
		/* set up env: USER, LOGNAME, HOME, PATH, whatever else */
		for (; *env; env++)
			putenv (*env);
		setenv ("USER", pw->pw_name, 1);
		setenv ("LOGNAME", pw->pw_name, 1);
		setenv ("HOME", pw->pw_dir, 1);
		confstr (_CS_PATH, path, sizeof (path));
		setenv ("PATH", path, 1);
		execv (argv[0], argv);
		/* exec failed */
		exit (EXIT_FAILURE);
	}
	/* we are the parent, so close the writers */
	closefd (out[1]);
	closefd (err[1]);
	SETFDS (proc->outfd, proc->errfd);
	clock_gettime (CLOCK_MONOTONIC, &proc->time);
	proc->time.tv_sec += PROCRUNTIME;
	heapup (heap, proc);
	return proc;
	fail:
	/* avoid hitting fd limit */
	closefd (out[0]);
	closefd (out[1]);
	closefd (err[0]);
	closefd (err[1]);
	free (proc);
	return NULL;
}

void cleanchild (const struct subproc *proc) {
	CLRFDS (proc->outfd, proc->errfd);
}

struct heaparg {
	pid_t pid;
	struct subproc *proc;
};

int spdel (const void *arg1, void *arg2) {
	struct subproc *proc = (struct subproc *)arg1;
	struct heaparg *arg = arg2;
	if (proc->pid == arg->pid) {
		arg->proc = proc;
		return 1;
	}
	return 0;
}

void chld (int signum, siginfo_t *sinfo, void *unused) {
	struct heaparg arg;
	/* this should only be ours, but if not, still need to reap */
	int status;
	if (sinfo->si_code != CLD_EXITED)
		return;
	arg.pid = sinfo->si_pid;
	if (waitpid (arg.pid, &status, 0) == -1)
		return;
	if (!WIFEXITED (status))
		return;
	/* also WIFSIGNALED(status) and WTERMSIG(status) to get signal */
	if (heapdelete (heap, spdel, &arg)) {
		int code;
		cleanchild (arg.proc);
		free (arg.proc);
		if ((code = WEXITSTATUS (status)) != EXIT_SUCCESS) {
			/* log this */
		}
	} else {
		/* log this */
		/* except that there may be many subprocesses, since we have to
		use sendmail */
	}
}

int _newlen (size_t *len, const size_t min) {
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
		EVTCOMP (EVTDIR);
		EVTCOMP ("/");
		EVTCOMP (evt);
		EVTCOMP (EVTEXT);
	} else {
		EVTCOMP (SYSEVTDIR);
		EVTCOMP ("/");
		EVTCOMP (evt);
		EVTCOMP (EVTEXT);
	}
#undef EVTCOMP
	if (_newlen (&size, len + 1)) {
		path = path ? realloc (path, size) : malloc (size) ;
		/* XXX */
		if (!path)
			exit (EXIT_FAILURE);
	}
	path[len] = '\0';
	for (i--; len > 0 && i >= 0; len -= lens[i], i--)
		memcpy (path + len - lens[i], paths[i], lens[i]);
	return path;
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

struct spout {
	int num;
	fd_set readfds, errorfds;
};
int spoutput (const void *arg1, void *arg2) {
	struct subproc *proc = (struct subproc *)arg1;
	struct spout *output = arg2;
	/* TODO */
	if (FD_ISSET (proc->outfd, &output->readfds)) {
		output->num--;
	}
	if (FD_ISSET (proc->errfd, &output->errorfds)) {
		output->num--;
	}
	return 1;
}

/*
simplest way to do this is if this is called as
runevent evtname envname=value...
or runevent evtname args...
either way, different events will have different semantics
*/
/*
1. get UID_MIN/MAX from login.defs
2. register CHLD handler
3. run system handler
4. getpwent()
5. if there are users to try
a.	if there are slots available, run handler
6. if there are processes running
a.	select() on subprocs' fds and next signal time
*/
int main (int argc, char **argv) {
	struct sigaction sa;
	struct passwd *pw;
	struct timespec now;
	struct subproc *proc;
	struct stat f;
	int i = 1, done = 0;
	char *args[2], *env[argc - i];

	/* XXX */
	if (argc < 2)
		return EXIT_FAILURE;

	/* set up argv and env */
	evt = argv[i];
	/* argv[0] will be set below */
	args[1] = NULL;
	for (; i < argc; i++)
		env[i] = argv[i];
	env[i] = NULL;

	getuidrange ();

	/* register SIGCHLD handler */
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = chld;
	sigemptyset (&sa.sa_mask);
	/* XXX */
	if (sigaction (SIGCHLD, &sa, NULL) == -1)
		return EXIT_FAILURE;

	/* set up our priority queue */
	heap = heapalloc (-1, MAXPROCS, sizeof (struct subproc *), spcmp);

	clock_gettime (CLOCK_MONOTONIC, &now);

	/* try running system event handler */
	args[0] = evtpath (NULL);
	if (stat (args[0], &f) == 0) {
		if (!(proc = runevent (NULL, args, env))) {
			/* log this */
		}
	}

	/* now the main loop */
	while (1) {
		clock_gettime (CLOCK_MONOTONIC, &now);
		if (done || heapcount (heap) == MAXPROCS) {
			struct timespec timeout;
			struct spout output;
			if (!heappeek (heap, &proc))
				break;
			output.readfds = readfds;
			output.errorfds = errorfds;
			tsdiff (&timeout, &proc->time, &now);
			if (timeout.tv_sec < 0) {
				if (proc->status == SPRUN) {
					kill (proc->pid, SIGTERM);
					heapdown (heap, NULL);
					memcpy (&proc->time, &now, sizeof (now));
					proc->time.tv_sec += PROCSIGTIME;
					proc->status = SPSIG;
					heapup (heap, &proc);
					/* will CHLD get delivered? */
					/*waitpid (proc->pid, &i, 0);*/
				} else {
					kill (proc->pid, SIGKILL);
				}
				/* timeout is negative, so don't select() */
				/* if we just sent KILL, we might not get the
				CHLD right away. maybe waitpid()? */
				continue;
			}
			output.num = pselect (nfds,
				&output.readfds, NULL, &output.errorfds,
				&timeout, NULL);
			while (output.num) {
				i = heapsearch (heap, NULL, i, spoutput, &output);
				/* this should not happen */
				if (i < 0)
					break;
			}
			continue;
		}
		if (!(pw = getpwent ())) {
			done = 1;
			endpwent ();
			continue;
		}
		if (!USEROK (pw))
			continue;
		/* run user handler */
		args[0] = evtpath (pw);
		if (stat (args[0], &f) == 0) {
			if (!(proc = runevent (NULL, args, env))) {
				/* log this */
			}
		}
	}
	return EXIT_SUCCESS;
}
