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
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>

/* specify -I or -L or whatever it is */
#include <bheap.h>

#ifndef CONFIGFILE
#define CONFIGFILE "/etc/runevents.conf"
#endif

#ifndef NDEBUG
#define DEBUG(f,...) \
	fprintf (stderr, "%s:%d %s() " f "\n", \
		__FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define DEBUG(f,...)
#endif

char *skipspaces (char *s, int n) {
	while (*s && isspace (*s))
		s += n;
	return s;
}

/*
 * configuration format similar to login.defs
 * KEY  "value" # comment
 */

enum {
	T_FREE,
	T_INT,
	T_STR
};

struct conf {
	char *name;
	int type;
	char *str;
	int value;
};

int confcmp (const void *name, const void *c) {
	return strcmp ((const char *)name, ((const struct conf *)c)->name);
}

struct conf *_cget (const char *name, struct conf **c, size_t num, size_t sz) {
	return (struct conf *)bsearch (name, c, num, sz, confcmp);
}

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

		if (r == 0)
			continue;

		p = skipspaces (line, 1);
		if ((c = strpbrk (p, "\n#")))
			r = c - p;
		else
			r -= p - line;

		if (r == 0)
			continue;

		*c = '\0';

		/* find whitespace after key */
		if (!(c = strpbrk (p, "\t\v\f ")))
			continue;

		/* length of name */
		if ((l = c - p) == 0)
			continue;

		/* NUL terminate the key so we can use it */
		*c = '\0';
		cfg = _cget (p, config, num, sz);
		if (!cfg)
			continue;

		/* find start of value */
		p += l + 1;
		r -= l + 1;
		c = skipspaces (c + 1, 1);
		if (!*c)
			continue;

		if (*c == '"') {
			char *e = strpbrk (c + 1, "\"");
			c++;
			if (e)
				*e = '\0';
		}

		if (cfg->type == T_INT)
			cfg->value = atoi (c);
		else if (cfg->type == T_STR)
			cfg->str = strdup (c);
	}
	fclose (f);
	free (line);
	return 1;
}

static struct conf configuration[] = {
	{ "EVT_EXT", T_STR, ".handler" },
	{ "GROUP", T_STR, "" },
	{ "LOGIN_DEFS", T_STR, "/etc/login.defs" },
	/*{ "MAIL_HEADER", T_STR, "This is to inform you about %n" },
	{ "MAIL_SUBJECT", T_STR, "runevent: %n" }, */
	{ "MAILER", T_STR, "/usr/bin/mail" },
	{ "MAX_PROCS", T_INT, NULL, 4 },
	{ "NICE", T_INT, NULL, 0 },
	{ "PROC_RUN_TIME", T_INT, NULL, 120 },
	{ "PROC_SIG_TIME", T_INT, NULL, 5 },
	/*{ "RLIMIT", T_INT, NULL, 0 },*/
	{ "SYS_DIR", T_STR, "/" },
	{ "SYS_EVT_DIR", T_STR, "/etc/events.d" },
	{ "UID_MAX_KEY", T_STR, "UID_MAX" },
	{ "UID_MIN_KEY", T_STR, "UID_MIN" },
	{ "USER_EVT_DIR", T_STR, "events.d" },
	{ "USER_NICE", T_INT, NULL, 0 },
	/*{ "USER_RLIMIT", T_INT, NULL, 0 }*/
};

#define PNSZ(s) &s, sizeof (s) / sizeof (*(s)), sizeof (*(s))

#ifndef NDEBUG
static void _checkconfiguration (const struct conf *c, size_t n, size_t sz) {
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
#endif

struct conf *cget (const char *name) {
	return _cget (name, PNSZ (configuration));
}

int cfgvalue (const char *name) {
	struct conf *c = cget (name);
	return c ? c->value : 0;
}

char *cfgstr (const char *name) {
	struct conf *c = cget (name);
	return c ? c->str : NULL;
}

static struct conf uidrange[] = {
	{ "UID_MAX", T_INT, NULL, INT_MAX },
	{ "UID_MIN", T_INT, NULL, INT_MIN }
};

int getuidrange (void) {
	char *defs = cfgstr ("LOGIN_DEFS");
	return defs && parseconfig (defs, PNSZ (uidrange));
}

int uidmax (void) {
	struct conf *c = _cget ("UID_MAX", PNSZ (uidrange));
	return c->value;
}

int uidmin (void) {
	struct conf *c = _cget ("UID_MIN", PNSZ (uidrange));
	return c->value;
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

pid_t open3 (int *cin, int *cout, int *cerr, const struct passwd *pw, const char *dir, char * const *argv, char * const *env) {
	int in[2] = {-1}, out[2] = {-1}, err[2] = {-1};
	pid_t pid;
#define PIPEX(fd) do { \
	if ((c##fd) && pipe (fd) != 0) \
		goto fail; \
} while (0)
	PIPEX (in);
	PIPEX (out);
	PIPEX (err);
#undef PIPEX
	DEBUG ("run '%s' as '%s' (%d:%d)", argv[0], pw ? pw->pw_name : "root", pw ? pw->pw_uid : 0, pw ? pw->pw_gid : 0);
	if ((pid = fork ()) == -1)
		goto fail;
	if (pid == 0) {
		/* child */
		char path[128];
		if (dir && chdir (dir) != 0)
			exit (EXIT_FAILURE);
		if (!pw) {
			pw = getpwuid (0);
			setpriority (PRIO_PROCESS, getpid (),
				cfgvalue ("NICE"));
		} else {
			/* must be set before dropping privileges */
			setpriority (PRIO_PROCESS, getpid (),
				cfgvalue ("USER_NICE"));
			/* drop privileges */
			if (setgid (pw->pw_gid) != 0 || setuid (pw->pw_uid) != 0)
				exit (EXIT_FAILURE);
		}
		/* close unneeded fds */
#define CLODUP(fd,n,x) do { \
	if ((fd)[0] > -1) { \
		closefd ((fd)[x]); \
		dupfd ((fd)[!x], n); \
	} \
} while (0)
		/* close stdin writer, stdout and stderr readers */
		CLODUP (in, STDIN_FILENO, 1);
		CLODUP (out, STDOUT_FILENO, 0);
		CLODUP (err, STDERR_FILENO, 0);
#undef CLODUP
		/* close others */
		closefrom (3);
		/* set up the env */
		if (clearenv () != 0)
			exit (EXIT_FAILURE);
		if (env) {
			for (; *env; env++)
				putenv (*env);
		}
		/* set up USER, LOGNAME, HOME, PATH */
		setenv ("USER", pw->pw_name, 1);
		setenv ("LOGNAME", pw->pw_name, 1);
		setenv ("HOME", pw->pw_dir, 1);
		confstr (_CS_PATH, path, sizeof (path));
		setenv ("PATH", path, 1);
		execv (argv[0], argv);
		fprintf (stderr, "exec '%s' failed: %s", argv[0], strerror (errno));
		/* should not happen */
		exit (EXIT_FAILURE);
	}
	/* parent */
	DEBUG ("pid=%d", pid);
#define CLOCP(fd,x) do { \
	if (c##fd) { \
		closefd ((fd)[x]); \
		*(c##fd) = (fd)[!x]; \
	} \
} while (0)
	/* close stdin writer, stdout and stderr readers */
	CLOCP (in, 0);
	CLOCP (out, 1);
	CLOCP (err, 1);
	return pid;
#undef CLOCP
	fail:
#define CLOSEFDS(fd) do { \
	if ((c##fd) && (fd)[0] != -1) { \
		closefd ((fd)[0]); \
		closefd ((fd)[1]); \
		*(c##fd) = -1; \
	} \
} while (0)
	CLOSEFDS (in);
	CLOSEFDS (out);
	CLOSEFDS (err);
#undef CLOSEFDS
	return -1;
}

/* keep track of everything we need to keep track of for subprocs */
struct subproc {
	pid_t pid;
	uid_t uid;
	gid_t gid;
	/* readers for stdout and stderr */
	int readfd, errorfd;
	/*
	 * if status == SPRUN, signal with TERM
	 * if status == SPSIG, signal with KILL
	 */
	enum { SPRUN, SPSIG } status;
	/* clock_gettime(CLOCK_MONOTONIC) */
	struct timespec time;
	char *path;
	/* mail */
	struct {
		pid_t pid;
		int infd;
	} mail;
};

pid_t initmail (struct subproc *proc, const char *subject) {
	struct passwd *pw;
	/* How many arguments to the mailer?
	 * 1             2  3         4  5    6
	 * /usr/bin/mail -s "subject" -- user NULL
	 */
	char *args[6];
	if (proc->mail.pid)
		return proc->mail.pid;
	if (!(pw = getpwuid (proc->uid)))
		return -1;
	args[0] = cfgstr ("MAILER");
	args[1] = "-s";
	args[2] = (char *)subject;
	args[3] = "--";
	args[4] = pw->pw_name;
	args[5] = NULL;
	proc->mail.pid = open3 (&proc->mail.infd, NULL, NULL, pw, NULL, (char * const *)args, NULL);
	/* MAIL_HEADER */
	if (proc->mail.pid > -1) {
		dprintf (proc->mail.infd, "This is to inform you about %s\n\n",
			proc->path);
	}
	return proc->mail.pid;
}

static char *evt;
static fd_set fdset;
static int nfds = 0;
static bheap_t *heap;

#define SETFDS(r,e) do { \
	if ((r) >= nfds) nfds = (r) + 1; \
	if ((e) >= nfds) nfds = (e) + 1; \
	FD_SET (r, &fdset); \
	FD_SET (e, &fdset); \
} while (0)
#define CLRFDS(r,e) do { \
	FD_CLR (r, &fdset); \
	FD_CLR (e, &fdset); \
	while (nfds > 0 && !FD_ISSET (nfds - 1, &fdset)) \
		nfds--; \
} while (0)

int spcmp (const void *arg1, const void *arg2) {
	const struct subproc *a = *(const struct subproc **)arg1,
		*b = *(const struct subproc **)arg2;
	return a->time.tv_sec == b->time.tv_sec ?
		a->time.tv_nsec - b->time.tv_nsec :
		a->time.tv_sec - b->time.tv_sec;
}

struct subproc *runevent (const struct passwd *pw, char * const *argv, char * const *env) {
	struct subproc *proc = calloc (1, sizeof (struct subproc));
	proc->mail.infd = -1;
	proc->status = SPRUN;
	if (pw) {
		proc->uid = pw->pw_uid;
		proc->gid = pw->pw_gid;
	}
	proc->pid = open3 (NULL, &proc->readfd, &proc->errorfd, pw,
		pw ? pw->pw_dir : cfgstr ("SYS_DIR"),
		argv, env);
	/* XXX */
	if (proc->pid == -1)
		goto fail;
	DEBUG ("open3 '%s' pid %d with stdout piped to %d and stderr to %d", argv[0], proc->pid, proc->readfd, proc->errorfd);
	SETFDS (proc->readfd, proc->errorfd);
	clock_gettime (CLOCK_MONOTONIC, &proc->time);
	proc->time.tv_sec += cfgvalue ("PROC_RUN_TIME");
	proc->path = strdup (argv[0]);
	heapup (heap, &proc);
	return proc;
	fail:
	free (proc);
	return NULL;
}

void cleanchild (struct subproc *proc) {
	DEBUG ("reap %d", proc->pid);
	CLRFDS (proc->readfd, proc->errorfd);
	free (proc->path);
	if (proc->mail.pid > 0) {
		closefd (proc->mail.infd);
		proc->mail.pid = -1;
	}
}

struct heaparg {
	pid_t pid;
	struct subproc *proc;
};

int spdel (const void *arg1, void *arg2) {
	struct subproc *proc = *(struct subproc **)arg1;
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
	int status, code;
	int sen = errno;
	/* actually don't care if it was stopped or the like */
	arg.pid = sinfo->si_pid;
	DEBUG ("pid %d", arg.pid);
	if (waitpid (arg.pid, &status, 0) == -1) {
		DEBUG ("waitpid failed: %s", strerror (errno));
		goto done;
	}
	if (WIFEXITED (status)) {
		if ((code = WEXITSTATUS (status)) != EXIT_SUCCESS) {
			/* log this */
			DEBUG ("exited with status %d", code);
		}
	} else if (WIFSIGNALED (status)) {
		code = WTERMSIG (status);
		/* log this */
		DEBUG ("child received signal %d", code);
	}
	if (heapdelete (heap, spdel, &arg)) {
		int code;
		if ((code = WEXITSTATUS (status)) != EXIT_SUCCESS) {
			/* log this */
		}
		cleanchild (arg.proc);
		free (arg.proc);
	} else {
		DEBUG ("%d is not ours?!", arg.pid);
		/* log this */
		/* except that there may be many subprocesses, since we have to
		use sendmail */
	}
	done:
	errno = sen;
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

static int validfd (int fd) {
	return fcntl (fd, F_GETFD) != -1 || errno != EBADF;
}

static void readfd (int *fd, int tofd, fd_set *fds, int *num) {
	if (*fd >= 0 && FD_ISSET (*fd, fds)) {
		char buf[1024];
		ssize_t n;
		do {
			n = read (*fd, buf, sizeof (buf) - 1);
			if (n == -1) {
				if (errno == EINTR)
					continue;
				break;
			}
			/*buf[n] = '\0';*/
			if (tofd != -1)
				write (tofd, buf, n);
		} while (n == sizeof (buf) - 1);
		if (n == 0) {
			FD_CLR (*fd, &fdset);
			*fd = -1;
		}
		(*num)--;
	}
}

struct spout {
	int num;
	fd_set fdset;
};
int spoutput (const void *arg1, void *arg2) {
	struct subproc *proc = *(struct subproc **)arg1;
	struct spout *output = arg2;
	/* MAIL_SUBJECT */
	initmail (proc, "runevent");
	readfd (&proc->readfd, proc->mail.infd, &output->fdset, &output->num);
	readfd (&proc->errorfd, proc->mail.infd, &output->fdset, &output->num);
	return 0;
}

static struct subproc *runif (const struct passwd *pw, char **argv, char * const *env) {
	struct stat f;
	struct subproc *proc;

	argv[0] = evtpath (pw);
	if (stat (argv[0], &f) != 0)
		return NULL;

	if (f.st_uid != (pw ? pw->pw_uid : 0)) {
		/* log this */
		DEBUG ("'%s' is not owned by %s", argv[0], pw ? pw->pw_name : "root");
		return NULL;
	}

	if (!(proc = runevent (pw, argv, env))) {
		/* log this */
	}

	return proc;
}

int userok (const struct passwd *pw) {
	struct group *gr;
	char **mem;
	char *grnam;

	if (pw->pw_uid < uidmin () || pw->pw_uid > uidmax ())
		return 0;

	grnam = cfgstr ("GROUP");
	if (!*grnam)
		return 1;

	/* silently ignore */
	if (!(gr = getgrnam (grnam)))
		return 1;

	DEBUG ("checking if %s is a member of %s", pw->pw_name, grnam);

	if (pw->pw_gid == gr->gr_gid)
		return 1;

	for (mem = gr->gr_mem; *mem; mem++) {
		if (strcmp (pw->pw_name, *mem) == 0)
			return 1;
	}

	return 0;
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
	int i, done = 0;
	int maxprocs, procsigtime;
	char *args[2], *env[argc - 1];

	/* XXX */
	if (argc < 2)
		return EXIT_FAILURE;

#ifdef NDEBUG
	/* XXX */
	if (getuid () != 0)
		return EXIT_FAILURE;
#else
	_checkconfiguration (PNSZ (configuration));
	_checkconfiguration (PNSZ (uidrange));
#endif

	/* set up argv and env */
	evt = argv[1];
	/* argv[0] will be set below */
	args[1] = NULL;
	for (i = 0; i < argc - 2; i++)
		env[i] = argv[i + 2];
	env[i] = NULL;

	FD_ZERO (&fdset);

	parseconfig (CONFIGFILE, PNSZ (configuration));

	maxprocs = cfgvalue ("MAX_PROCS");
	if (maxprocs < 1) {
		fprintf (stderr, "%s: MAX_PROCS must be at least 1\n", argv[0]);
		maxprocs = 1;
	}

	procsigtime = cfgvalue ("PROC_SIG_TIME");
	if (procsigtime < 1) {
		fprintf (stderr, "%s: PROC_SIG_TIME must be at least 1\n", argv[0]);
		procsigtime = 1;
	}

	getuidrange ();
	DEBUG ("got UID range %d-%d", uidmin (), uidmax ());

	/* register SIGCHLD handler */
	sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
	sa.sa_sigaction = chld;
	sigemptyset (&sa.sa_mask);
	/* XXX */
	if (sigaction (SIGCHLD, &sa, NULL) == -1)
		return EXIT_FAILURE;

	/* set up our priority queue */
	heap = heapalloc (-1, maxprocs, sizeof (struct subproc *), spcmp);

	clock_gettime (CLOCK_MONOTONIC, &now);

	/* try running system event handler */
	proc = runif (NULL, args, env);

	/* now the main loop */
	while (1) {
		clock_gettime (CLOCK_MONOTONIC, &now);
		if (done || heapcount (heap) == maxprocs) {
			struct timespec timeout;
			struct spout output;
			if (!heappeek (heap, &proc))
				break;
			output.fdset = fdset;
			tsdiff (&timeout, &proc->time, &now);
			if (timeout.tv_sec < 0) {
				if (proc->status == SPRUN) {
					DEBUG ("kill -TERM %d", proc->pid);
					kill (proc->pid, SIGTERM);
					heapdown (heap, NULL);
					proc->time = now;
					proc->time.tv_sec += procsigtime;
					proc->status = SPSIG;
					heapup (heap, &proc);
				} else {
					/* if we just sent KILL, we might not
					get SIGCHLD right away
					will we get SIGCHLD if we waitpid()? */
					DEBUG ("kill -KILL %d", proc->pid);
					kill (proc->pid, SIGKILL);
					/*waitpid (proc->pid, &i, 0);*/
				}
				/* timeout is negative, so don't select() */
				continue;
			}
			do {
				output.num = pselect (nfds,
					&output.fdset, NULL, NULL /* check too? */,
					&timeout, NULL);
			} while (output.num == -1 && errno == EINTR);
			if (output.num < 0) {
				DEBUG ("pselect error: %s", strerror (errno));
				continue;
			}
			/* iterate over items in the heap */
			heapsearch (heap, NULL, 0, spoutput, &output);
			continue;
		}
		if (!(pw = getpwent ())) {
			done = 1;
			endpwent ();
			continue;
		}
		if (!userok (pw))
			continue;
		/* run user handler */
		proc = runif (pw, args, env);
	}
	return EXIT_SUCCESS;
}
