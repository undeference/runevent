#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
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

/* specify -I or -L or whatever it is */
#include <bheap.h>

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

/* how long a handler is allowed to run */
#ifndef PROCRUNTIME
#define PROCRUNTIME 120
#endif

/* maximum time to wait for a signalled handler to terminate */
#ifndef PROCSIGTIME
#define PROCSIGTIME 5
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

void penv (const char *n, const char *v) {
	size_t ln = strlen (n), lv = strlen (v) + 1 /* including NUL */;
	char buf[ln + lv + 1];
	memcpy (buf, n, ln);
	buf[ln] = '=';
	memcpy (buf + 2, v, lv);
	putenv (buf);
}

static char *evt;
static fd_set readfds, errorfds;

/* keep track of everything we need to keep track of for subprocs */
struct subproc {
	struct subproc *prev, *next;
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
static struct subproc *tail = NULL;
static size_t numprocs = 0;

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
	clock_gettime (CLOCK_MONOTONIC, &proc->time);
	/* now do the fork */
	proc->pid = fork ();
	/* XXX */
	if (proc->pid == -1)
		goto fail;
	if (proc->pid) {
		/* we are the parent, so close the writers */
		closefd (out[1]);
		closefd (err[1]);
		FD_SET (proc->outfd, &readfds);
		FD_SET (proc->errfd, &errorfds);
	} else {
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
		for (; **env; env++)
			putenv (*env);
		/* set up env: USER, LOGNAME, HOME, PATH, whatever else */
		penv ("USER", pw->pw_name);
		penv ("LOGNAME", pw->pw_name);
		penv ("HOME", pw->pw_dir);
		confstr (_CS_PATH, path, sizeof (path));
		penv ("PATH", path);
		for (; *env; env++)
			putenv (*env);
		execv (argv[0], argv);
		/* exec failed */
		exit (EXIT_FAILURE);
	}
	/* doubly linked list */
	proc->prev = tail;
	tail = proc;
	numprocs++;
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
	numprocs--;
	FD_CLR (proc->outfd, &readfds);
	FD_CLR (proc->errfd, &errorfds);
	/* report */
}

#define SPLICELL(ll) do { \
	if (tail == (ll)) tail = (ll)->prev; \
	if ((ll)->prev) (ll)->prev->next = (ll)->next; \
	if ((ll)->next) (ll)->next->prev = (ll)->prev; \
} while (0)

void chld (int signum, siginfo_t *sinfo, void *unused) {
	struct subproc *proc;
	/* this should only be ours, but if not, still need to reap */
	pid_t pid;
	int status, code;
	int serrno = errno;
	if (sinfo->si_code != CLD_EXITED)
		return;
	pid = sinfo->si_pid;
	if (waitpid (pid, &status, 0) == -1)
		return;
	if (!WIFEXITED (status))
		return;
	/* also WIFSIGNALED(status) and WTERMSIG(status) to get signal */
	code = WEXITSTATUS (status);
	errno = serrno;
	for (proc = tail; proc; proc = proc->prev) {
		if (proc->pid == pid) {
			SPLICELL (proc);
			cleanchild (proc);
			free (proc);
			break;
		}
	}
}
/*
struct sigaction sa;
sa.sa_flags = SA_SIGINFO;
sa.sa_sigaction = chld;
sigemptyset (&sa.sa_mask);
if (sigaction (SIGCHLD, &sa, NULL) == -1) ...
*/