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

/*
 * Native wrappers for setuid/getuid
 */

#include <jni.h>
#include "com_netscape_osutil_UserID.h"
#include "unixdefs.h"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <stdlib.h>

/*
 * Throw an IllegalArgumentException 
 */
void
unix_throw_exception(JNIEnv *env, const char *exception, const char *reason)
{
	jclass exc;

	exc = (*env)->FindClass(env, exception);
	if (exc) /* If unable to find the new exception class, give up. */
		(*env)->ThrowNew(env, exc, reason);
}

/*
 * Convert a jstring name into a uid_t value
 */
static uid_t
name_to_uid(JNIEnv *env, jstring name) 
{
	const char *username = (*env)->GetStringUTFChars(env, name, 0);
	struct passwd *pw;
	int ret;

	if (NULL == username) {
		unix_throw_exception(env, ILLARG, "can't convert username");
		return -1;
	}

	pw = getpwnam(username);

	if (NULL == pw) {
		/* XXX I suppose the failed user name would be useful here */
		unix_throw_exception(env, ILLARG, "no such user");
		return -1;
	}

	ret = pw->pw_uid;
	free(pw);
	return ret;
}

/*
 * Class:     com_netscape_osutil_UserID
 * Method:    get
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
Java_com_netscape_osutil_UserID_get(JNIEnv *env, jclass cls)
{
	return getuid();
}

/*
 * Class:     com_netscape_certsrv_unix_UserID
 * Method:    getEffective
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
Java_com_netscape_osutil_UserID_getEffective(JNIEnv *env, jclass cls)
{
	return geteuid();
}

/*
 * Class:     com_netscape_certsrv_unix_UserID
 * Method:    set
 * Signature: (I)Z
 */
JNIEXPORT void JNICALL
Java_com_netscape_osutil_UserID_set__I(JNIEnv *env, jclass cls, jint id)
{
	int status = setuid(id);

	if (status != 0) {
		switch (errno) {
		case EINVAL:
			unix_throw_exception(env, ILLARG, "bad uid value");
			break;
		case EPERM:
			unix_throw_exception(env, SECURITY, "permission denied");
			break;
		} 
	}
}

/*
 * Class:     com_netscape_certsrv_unix_UserID
 * Method:    set
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT void JNICALL
Java_com_netscape_osutil_UserID_set__Ljava_lang_String_2(JNIEnv *env, jclass cls, jstring name)
{
	int id = name_to_uid(env, name);

	if (id >= 0)
		Java_com_netscape_osutil_UserID_set__I(env, cls, id);
}

/*
 * Class:     com_netscape_certsrv_unix_UserID
 * Method:    setEffective
 * Signature: (I)Z
 */
JNIEXPORT void JNICALL
Java_com_netscape_osutil_UserID_setEffective__I(JNIEnv *env, jclass cls, jint id)
{
	int status = seteuid(id);

	if (status != 0) {
		switch (errno) {
		case EINVAL:
			unix_throw_exception(env, ILLARG, "bad uid value");
			break;
		case EPERM:
			unix_throw_exception(env, SECURITY, "permission denied");
			break;
		} 
	}
}

/*
 * Class:     com_netscape_certsrv_unix_UserID
 * Method:    setEffective
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT void JNICALL
Java_com_netscape_osutil_UserID_setEffective__Ljava_lang_String_2(JNIEnv *env, jclass cls, jstring name)
{
	int id = name_to_uid(env, name);

	if (id >= 0)
		Java_com_netscape_osutil_UserID_setEffective__I(env, cls, id);
}

