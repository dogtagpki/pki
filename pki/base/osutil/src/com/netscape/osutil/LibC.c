// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
#include <jni.h>
#include "com_netscape_osutil_LibC.h"
#include "unixdefs.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>


/*
 * Class:     com_netscape_osutil_LibC
 * Method:    getpid
 * Signature: ()I
 *
 * Return the current pid
 */
JNIEXPORT jint JNICALL 
Java_com_netscape_osutil_LibC_getpid(JNIEnv *env, jclass cls)
{
	return getpid();
}

/*
 * Class:     com_netscape_osutil_LibC
 * Method:    getppid
 * Signature: ()I
 *
 * Return the parent pid
 */
JNIEXPORT jint JNICALL 
Java_com_netscape_osutil_LibC_getppid(JNIEnv *env, jclass cls)
{
	return getppid();
}

/*
 * Class:     com_netscape_osutil_LibC
 * Method:    setpgrp
 * Signature: ()I
 *
 * Change the current process group and disconnect from the tty
 */
JNIEXPORT jint JNICALL 
Java_com_netscape_osutil_LibC_detach(JNIEnv *env, jclass cls)
{
	int sid, pid;

	pid = fork();

	if (pid != 0) {
		if (pid > 0) {
			exit(0);
		} else {
			/* Adding perror here might be helpful */
			unix_throw_exception(env, RUNTIME, "can't fork");
			return -1;
		}
	} else {
		sid = setsid();
		if (sid < 0) {
			unix_throw_exception(env, SECURITY, "permission denied");
		}
		return sid;
	}
}

