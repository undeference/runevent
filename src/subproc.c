#include "config.h"
#include "subproc.h"

/* close parent fds */
void closefrom (int min) {
	struct dirent *f;
	DIR *d = opendir ("/dev/fd");
	int fd;
	if (!d) {
		syslog (LOG_WARNING, "cannot open /dev/fd - fds remain open");
		return;
	}

	while ((f = readdir (d))) {
		/* . or .. */
		if (!isdigit (f->d_name[0]))
			continue;

		fd = atoi (f->d_name);
		if (fd >= min)
			closefd (fd);
	}
	closedir (d);
}

/* set up a clean environment */
void setupenv (const struct passwd *pw, char * const *env) {
	char path[256];
	if (clearenv () != 0) {
		syslog (LOG_CRIT, "clearenv failed");
		exit (EXIT_FAILURE);
	}

	if (env) {
		for (; *env; env++)
			putenv (*env);
	}

	setenv ("USER", pw->pw_name, 1);
	setenv ("LOGNAME", pw->pw_name, 1);
	setenv ("HOME", pw->pw_dir, 1);
	confstr (_CS_PATH, path, sizeof (path));
	setenv ("PATH", path, 1);
}

/* switch user */
int su (const struct passwd *pw) {
	/* assert? */
	if (!pw) {
		syslog (LOG_CRIT, "su with no target");
		return 0;
	}

	/* `cd` */
	if (chdir (pw->pw_dir) != 0) {
		syslog (LOG_ERR, "chdir('%s'): %s",
			pw->pw_dir, strerror (errno));
		return 0;
	}

	/* switch to user's group */
	if (setgid (pw->pw_gid) != 0) {
		syslog (LOG_ERR, "setgid(%d): %s",
			pw->pw_gid, strerror (errno));
		return 0;
	}

	/* switch to user's id */
	if (setuid (pw->pw_uid) != 0) {
		syslog (LOG_ERR, "setuid(%d): %s",
			pw->pw_uid, strerror (errno));
		return 0;
	}

	/* success */
	return 1;
}

int nice (int niceness) {
	errno = 0;
	setpriority (PRIO_PROCESS, getpid (), niceness);
	if (errno) {
		syslog (LOG_ERR, "nice %d: %s", niceness, strerror (errno));
		return 0;
	}
	return 1;
}

/* start a subprocess, getting its stdin, stdout, stderr */
pid_t open3 (int *cin, int *cout, int *cerr, const struct passwd *pw, char * const *argv, char * const *env) {
	int in[2] = {-1}, out[2] = {-1}, err[2] = {-1};
	pid_t pid;

	/* save some typing */
#define PIPEX(fd) do { \
	if ((c##fd) && pipe (fd) != 0) \
		goto fail; \
} while (0)
	PIPEX (in);
	PIPEX (out);
	PIPEX (err);
#undef PIPEX

	DEBUG ("run '%s' as '%s' (%d:%d)", argv[0], pw ? pw->pw_name : "root", pw ? pw->pw_uid : 0, pw ? pw->pw_gid : 0);

	if ((pid = fork ()) == -1) {
		syslog (LOG_ERR, "fork() failed: %s", strerror (errno));
		goto fail;
	}

	if (pid == 0) {
		/* child */
		/* system run */
		if (!pw) {
			/* what if this fails? */
			pw = getpwuid (0);
			nice (cfgvalue ("NICE"));
		} else {
			nice (cfgvalue ("USER_NICE"));

			/* drop privileges */
			if (!su (pw))
				exit (EXIT_FAILURE);
		}
		/* set up std fds */
#define CLODUP(fd,n,x) do { \
	if ((fd)[0] > -1) { \
		closefd ((fd)[x]); \
		dupfd ((fd)[!x], n); \
	} \
} while (0)
		CLODUP (in, STDIN_FILENO, 1);
		CLODUP (out, STDOUT_FILENO, 0);
		CLODUP (err, STDERR_FILENO, 0);
#undef CLODUP

		/* close other fds */
		closefrom (STDERR_FILENO + 1);

		setupenv (pw, env);
		/* replace process with subprocess */
		execv (argv[0], argv);
		/* error */
		fprintf (stderr, "exec '%s' failed: %s",
			argv[0], strerror (errno));
		exit (EXIT_FAILURE);
	}
	/* the child does not get here */
	DEBUG ("pid=%d", pid);

	/* we only want one side of the pipes */
#define CLOCP(fd,x) do { \
	if (c##fd) { \
		closefd ((fd)[x]); \
		*(c##fd) = (fd)[!x]; \
	} \
} while (0)
	CLOCP (in, 0);
	CLOCP (out, 1);
	CLOCP (err, 1);
#undef CLOCP
	return pid;

	fail:
#define CLOSEFDS(fd) do {\
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

pid_t initmail (struct subproc *proc, const char *subject) {
	struct passwd *pw;
	/* How many arguments to the mailer?
	 * 1             2  3         4  5    6
	 * /usr/bin/mail -s "subject" -- user NULL
	 */
	char *args[6];

	/* already running */
	if (proc->mail.pid)
		return proc->mail.pid;

	/* no such user? */
	if (!(pw = getpwuid (proc->uid)))
		return -1;

	/* set up args */
	args[0] = cfgstr ("MAILER");
	args[1] = "-s";
	args[2] = (char *)subject;
	args[3] = "--";
	args[4] = pw->pw_name;
	args[5] = NULL;

	proc->mail.pid = open3 (&proc->mail.fd[0], NULL, NULL, pw,
		(char * const *)args, NULL);
	syslog (LOG_INFO, "started '%s' for '%s'", args[0], proc->path);

	/* MAIL_HEADER */
	if (proc->mail.pid > -1) {
		dprintf (proc->mail.fd[0],
			"This is to inform you about '%s'\n\n", proc->path);
	}

	return proc->mail.pid;
}

/* check <0 for failure */
__attribute__ ((format (printf, 2, 3))) int mail (struct subproc *proc, const char *fmt, ...) {
	int r = 0;
	va_list ap;

	if (!*fmt)
		return 0;

	va_start (ap, fmt);

	/* MAIL_SUBJECT */
	if (!sysrun) {
		fprintf (stderr, "%s[%d] says:  ", proc->path, proc->pid);
		vfprintf (stderr, fmt, ap);
	} else if (initmail (proc, "runevent"))
		r = vdprintf (proc->mail.fd[0], fmt, ap);
	else
		syslog (LOG_ERR, "unable to send mail for uid %d", proc->uid);
	va_end (ap);
	return r;
}


void readfd2 (struct subproc *proc, fd_set *fds, int *num) {
	size_t i;
	for (i = 0; *num && i < ARRAYN (proc->fd); i++) {
		char buf[1024];
		ssize_t n;

		if (proc->fd[i] < 0 || !FD_ISSET (proc->fd[i], fds))
			continue;

		do {
			TEMP_FAILURE_RETRY (n = read (proc->fd[i], buf,
				sizeof (buf) - 1));
			if (n == -1) {
				syslog (LOG_WARNING, "read output from '%s': %s",
					proc->path, strerror (errno));
				break;
			}
			if (n > 0) {
				buf[n] = '\0';
				mail (proc, "%s", buf);
			}
		} while (n == sizeof (buf) - 1);
		/* eof */
		if (n == 0) {
			FD_CLR (proc->fd[i], &fdset);
			closefd (proc->fd[i]);
			proc->fd[i] = -1;
		}
		(*num)--;
	}
}

/* clean up after the child has exited */
void cleanchild (struct subproc *proc) {
	DEBUG ("reap %d", proc->pid);
	CLRFDS (proc->fd);
	free (proc->path);

	/* mailer was started for this process */
	if (proc->mail.pid > 0) {
		closefd (proc->mail.fd[0]);
		proc->mail.pid = 0;
		proc->mail.fd[0] = -1;
	}
}
