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

#include <sys/resource.h>

/*
 * Class:     com_netscape_osutil_ResourceLimit
 * Method:    getHardLimit
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_netscape_osutil_ResourceLimit_getHardLimit
  (JNIEnv *env, jclass myclass, jint resource)
{
	struct rlimit limit;

	getrlimit(resource,&limit);
	return limit.rlim_max;
}

/*
 * Class:     com_netscape_osutil_ResourceLimit
 * Method:    getSoftLimit
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_netscape_osutil_ResourceLimit_getSoftLimit
  (JNIEnv *env, jclass myclass, jint resource)
{
	struct rlimit limit;

	getrlimit(resource,&limit);
	return limit.rlim_cur;
}


/*
 * Class:     com_netscape_certsrv_unix_ResourceLimit
 * Method:    setLimits
 * Signature: (III)I
 */
JNIEXPORT jint JNICALL Java_com_netscape_osutil_ResourceLimit_setLimits
  (JNIEnv *env, jclass myclass, jint resource, jint soft, jint hard)
{
	int r;
	struct rlimit limit;

	limit.rlim_cur = soft;
	limit.rlim_max = hard;
	r = setrlimit(resource,&limit);
	return r;
}

