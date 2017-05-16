/*
 *  WrapSix
 *  Copyright (C) 2008-2012  xHire <xhire@wrapsix.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

/**
 * Logs debugging stuff to stdout, but only when compiled with debug enabled.
 *
 * @param	msg	Formatted message
 * @param	...	Parameters to be included in the message
 */
void log_debug(const char *msg, ...)
{
#ifdef DEBUG
	va_list args;

	fprintf(stdout, "[Debug] ");

	va_start(args, msg);
	vfprintf(stdout, msg, args);
	va_end(args);

	fprintf(stdout, "\n");
#endif /* DEBUG */
}

/**
 * Logs information to stdout.
 *
 * @param	msg	Formatted message
 * @param	...	Parameters to be included in the message
 */
void log_info(const char *msg, ...)
{
	va_list args;

	fprintf(stdout, "[Info] ");

	va_start(args, msg);
	vfprintf(stdout, msg, args);
	va_end(args);

	fprintf(stdout, "\n");
}

/**
 * Logs warnings to stderr.
 *
 * @param	msg	Formatted message
 * @param	...	Parameters to be included in the message
 */
void log_warn(const char *msg, ...)
{
	va_list args;

	fprintf(stderr, "[Warning] ");

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);

	fprintf(stderr, "\n");
}

/**
 * Logs errors to stderr.
 *
 * @param	msg	Formatted message
 * @param	...	Parameters to be included in the message
 */
void log_error(const char *msg, ...)
{
	va_list args;

	fprintf(stderr, "[Error] ");

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);

	fprintf(stderr, "\n");
}
