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
#include <assert.h>
#include <string.h>
#include "com_netscape_osutil_OSUtil.h"

#ifdef XP_PC
#include <process.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include "base64.h"

JNIEXPORT jbyteArray JNICALL
Java_com_netscape_osutil_OSUtil_AtoB
    (JNIEnv* env, jclass this, jstring data)
{
    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    const char *dataChars;
    unsigned char *result=NULL;
    unsigned int olenp;

    dataChars = (*env)->GetStringUTFChars(env, data, NULL);
    if( dataChars == NULL ) {
        goto finish;
    }

    result = ATOB_AsciiToData(dataChars, &olenp);
    if (result == NULL) {
        goto finish;
    }

    handleBA = (*env)->NewByteArray(env, olenp);
    if(handleBA == NULL ) {
        goto finish;
    }
    handleBytes = (*env)->GetByteArrayElements(env, handleBA, NULL);
    if(handleBytes==NULL) {
        goto finish;
    }
    memcpy(handleBytes, result, olenp);

finish:
    if (dataChars) {
       (*env)->ReleaseStringUTFChars(env, data, dataChars);
    }
    if (result) {
       free(result);
    }
    if(handleBytes) {
        assert(handleBA);
        (*env)->ReleaseByteArrayElements(env, handleBA, handleBytes, 0);
    }
    return handleBA;
}

JNIEXPORT jstring JNICALL
Java_com_netscape_osutil_OSUtil_BtoA
    (JNIEnv* env, jclass this, jbyteArray data)
{
    char *result=NULL;
    jint len;
    jbyte *bytes=NULL;
    jstring retval = NULL;

    len = (*env)->GetArrayLength(env, data);
    bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if( bytes == NULL ) {
        goto finish;
    }

    result = BTOA_DataToAscii(bytes, len);
    if (result == NULL) {
        goto finish;
    }

    retval = (*env)->NewStringUTF(env, result);

finish:
    if (result) {
       free(result);
    }
    if(bytes) {
        (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    }
    return retval;
}

JNIEXPORT jint JNICALL
Java_com_netscape_osutil_OSUtil_getNTpid
	(JNIEnv *env, jobject this)
{
#ifdef XP_PC
	return _getpid();
#else
	assert( 0 );
	return 0;
#endif
}

JNIEXPORT jstring JNICALL
Java_com_netscape_osutil_OSUtil_getenv
    (JNIEnv* env, jclass this, jstring envName)
{
    const char* envNameChars=NULL;
    char *envValueChars;
    jstring retval = NULL;

    /* convert Java String environment name to char* */
    envNameChars = (*env)->GetStringUTFChars(env, envName, NULL);
    if( envNameChars == NULL ) {
        goto finish;
    }

    /* look up the environment variable. The returned pointer points into
     * the environment table, so must not be freed by the caller. */
    envValueChars = (char *) getenv(envNameChars);
    if( envValueChars == NULL ) {
        goto finish;
    }

    /* convert char* to Java string */
    retval = (*env)->NewStringUTF(env, envValueChars);

finish:
    if( envNameChars ) {
        (*env)->ReleaseStringUTFChars(env, envName, envNameChars);
    }
    return retval;
}

JNIEXPORT jint JNICALL
Java_com_netscape_osutil_OSUtil_getFileReadLock
(JNIEnv *env, jclass this, jstring filename)
{
#ifdef XP_PC
  return(0);  /* Do nothing on NT for now */
#else
  const char* filenameChars=NULL;
  int value = 0;

  struct flock lock;
  int fd;

  filenameChars = (*env)->GetStringUTFChars(env, filename, NULL);
  if (filenameChars == NULL) {
    value = -1;
    goto finish;
  }
   
  fd = open(filenameChars, O_RDONLY);
  lock.l_type = F_RDLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 50;
  if (fcntl(fd, F_SETLK, &lock) < 0)
  {
    value = -1;
    goto finish;
    /*    printf("Cannot set read lock.\n");
    printf("File is write locked by %ld\n", lock.l_pid);
    */
  }
  fcntl(fd, F_GETLK, &lock);
  switch (lock.l_type)
  {
  case F_RDLCK:
    value = 1;
    break;
  case F_WRLCK:
    value = -1;
    break;
  case F_UNLCK:
    value = 0;
    break;
  }
 finish:
  if( filenameChars ) {
    (*env)->ReleaseStringUTFChars(env, filename, filenameChars);
  }
  return value;
#endif
}

JNIEXPORT jint JNICALL
Java_com_netscape_osutil_OSUtil_getFileWriteLock
(JNIEnv *env, jclass this, jstring filename)
{
  const char* filenameChars=NULL;
  int value = 0;
#ifdef XP_PC
#else
  struct flock lock;
  int fd;
#endif

  filenameChars = (*env)->GetStringUTFChars(env, filename, NULL);
  if (filenameChars == NULL) {
    value = -1;
    goto finish;
  }
#ifdef XP_PC
#else
  
  fd = open(filenameChars, O_RDWR);
  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 50;
  if (fcntl(fd, F_SETLK, &lock) < 0) {
    value = -1;
    goto finish;
    /*    printf("Cannot set write lock\n");
     */
  }
  fcntl(fd, F_GETLK, &lock);
  switch (lock.l_type)
  {
  case F_RDLCK:  
    value = 1;
    break;
  case F_WRLCK:  
    value = 2;
    break;
  case F_UNLCK:  
    value = 0;
    break;
  }
#endif
 finish:
  if( filenameChars ) {
    (*env)->ReleaseStringUTFChars(env, filename, filenameChars);
  }
  return value;
}


JNIEXPORT jint JNICALL
Java_com_netscape_osutil_OSUtil_putenv
(JNIEnv* env, jclass this, jstring envName)
{
  const char* envNameChars=NULL;
  int value =0;

  envNameChars = (*env)->GetStringUTFChars(env, envName, NULL);
  if (envNameChars == NULL) {
    value = -1;
    goto finish;
  }

#ifdef XP_PC
  value = _putenv(envNameChars);
#else
  /* Ross 1/26 Are we trashing memory here?  Look at putenv implementation details */
  value = putenv (strdup(envNameChars));
#endif 

finish:
  if( envNameChars ) {
    (*env)->ReleaseStringUTFChars(env, envName, envNameChars);
  }
  return value;
}

JNIEXPORT void JNICALL
Java_com_netscape_osutil_OSUtil_nativeExit
(JNIEnv *env, jobject this, jint status)
{
	exit(status);
}
