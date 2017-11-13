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

#ifndef _CONFIG
#define _CONFIG
#include "runevent.h"

#ifndef CONFIGFILE
#define CONFIGFILE "/etc/runevents.conf"
#endif

#ifndef EVT_EXT
#define EVT_EXT ".handler"
#endif

#ifndef GROUP
#define GROUP ""
#endif

#ifndef LOGIN_DEFS
#define LOGIN_DEFS "/etc/login.defs"
#endif

#ifndef MAILER
#define MAILER "/etc/login.defs"
#endif

#ifndef SYS_DIR
#define SYS_DIR "/"
#endif

#ifndef SYS_EVT_DIR
#define SYS_EVT_DIR "/etc/events.d"
#endif

#ifndef UID_MAX_KEY
#define UID_MAX_KEY "UID_MAX"
#endif

#ifndef UID_MIN_KEY
#define UID_MIN_KEY "UID_MIN"
#endif

#ifndef USER_EVT_DIR
#define USER_EVT_DIR "events.d"
#endif

struct conf {
	char *name;
	enum {
		T_FREE,
		T_INT,
		T_STR
	} type;
	union {
		int num;
		char *str;
	} value;
};

char *skipspaces (char *s, int n);
int parseconfig (const char *file, struct conf **config, size_t num, size_t sz);
struct conf *cfgget (const char *name);
int cfgvalue (const char *name);
char *cfgstr (const char *name);
int readconfig (void);

#ifndef NDEBUG
void checkconfigs (void);
#endif

/* this does not really belong here */
int uidmax (void);
int uidmin (void);
#endif
