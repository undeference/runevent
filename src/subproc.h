#ifndef _SUBPROC
#define _SUBPROC
#include "runevent.h"

struct subproc {
	pid_t pid;
	uid_t uid;
	gid_t gid;
	/* readers for subprocess's stdout and stderr */
	int fd[2];
	/*
	 * if status == SPRUN, signal with TERM
	 * if status == SPSID, signal with KILL
	 * if status == SPEXITED, if has already exited
	 */
	enum {
		SPRUN,		/* signal with TERM */
		SPSIG,		/* signal with KILL */
		SPEXITED	/* already exited */
	} status;
	/* clock_gettime(CLOCK_MONOTONIC) */
	struct timespec time;
	char *path;
	struct {
		pid_t pid;
		int fd[1];
	} mail;
};

void closefrom (int min);
void setupenv (const struct passwd *pw, char * const *env);
int su (const struct passwd *pw);
pid_t open3 (int *cin, int *cout, int *cerr, const struct passwd *pw, char * const *argv, char * const *env);

pid_t initmail (struct subproc *proc, const char *subject);
__attribute__ ((format (printf, 2, 3))) int mail (struct subproc *proc, const char *fmt, ...);

void readfd2 (struct subproc *proc, fd_set *fds, int *num);
void cleanchild (struct subproc *proc);
#endif
