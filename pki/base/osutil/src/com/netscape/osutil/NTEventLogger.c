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
#include "com_netscape_osutil_NTEventLogger.h"
#include "EventMessages.h"

#include <process.h>
#include <stdlib.h>
#include <windows.h>


static void
throwMsg(JNIEnv *env, char *throwableClassName, char *message) {

    jclass throwableClass=NULL;
    jint result;

    /* validate arguments */
    assert(env!=NULL && throwableClassName!=NULL && message!=NULL);

    if(throwableClassName) {
        throwableClass = (*env)->FindClass(env, throwableClassName);

        /* make sure the class was found */
        assert(throwableClass != NULL);
    }
    if(throwableClass == NULL) {
        throwableClass = (*env)->FindClass(env, "java/lang/Exception");
    }
    assert(throwableClass != NULL);

    result = (*env)->ThrowNew(env, throwableClass, message);
    assert(result == 0);
}

/**
 * Returns an error message using the given error code. Returns NULL if
 * something goes wrong.
 * Use LocalFree() to free the returned string.
 */
static char*
errCodeToErrMsg(DWORD errCode)
{
    char *errBuf=NULL;
    DWORD numBytes;

    numBytes = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 
        NULL /* source */,
        errCode,
        0 /* language */,
        (LPTSTR) &errBuf /* this will be set to a new buffer */,
        0 /* min # bytes to allocate */,
        NULL /*arg list */ );

    if( numBytes > 0 ) {
        return errBuf;
    } else {
        assert(FALSE);
        return NULL;
    }
}

static void
throwFromErrCode(JNIEnv *env, DWORD errCode, char *context)
{
    char *wholeMsg;
    char *errMsg;
    BOOL needToFreeErrMsg=TRUE;

    errMsg = errCodeToErrMsg(errCode);

    if( context == NULL ) {
        context = "";
    }

    if( errMsg == NULL ) {
        needToFreeErrMsg = FALSE;
        errMsg = "";
    }

    wholeMsg= (char*)malloc( strlen(context) + strlen(errMsg) + 4);
    sprintf(wholeMsg, "%s : %s", context, errMsg);
    throwMsg(env, "java/lang/Exception", wholeMsg);

    /* cleanup */
    if(needToFreeErrMsg) {
        LocalFree(errMsg);
    }
    free(wholeMsg);
}


/**
 * Converts a byte array to a Windows HANDLE. Returns NULL if something
 * goes wrong.
 */
static HANDLE
byteArrayToHandle(JNIEnv *env, jbyteArray handleBA) {

    HANDLE handle=NULL;
    jbyte *bytes=NULL;
    jint len;

    assert(env!=NULL && handleBA!=NULL);

    len = (*env)->GetArrayLength(env, handleBA);
    assert(len == sizeof(HANDLE));
    if( len != sizeof(HANDLE) ) {
        goto finish;
    }

    bytes = (*env)->GetByteArrayElements(env, handleBA, NULL);
    if( bytes == NULL ) {
        goto finish;
    }

    memcpy(&handle, bytes, len);

finish:
    if(bytes) {
        (*env)->ReleaseByteArrayElements(env, handleBA, bytes, JNI_ABORT);
    }
    return handle;
}

/**
 * Converts a Windows HANDLE to a Java byte array
 */
static jbyteArray
handleToByteArray(JNIEnv *env, HANDLE handle) {
    jbyteArray handleBA=NULL;
    jbyte *bytes=NULL;

    handleBA = (*env)->NewByteArray(env, sizeof(HANDLE));
    if(handleBA == NULL ) {
        goto finish;
    }

    bytes = (*env)->GetByteArrayElements(env, handleBA, NULL);
    if(bytes == NULL) {
        goto finish;
    }

    memcpy(bytes, &handle, sizeof(handle));

finish:
    if(bytes) {
        (*env)->ReleaseByteArrayElements(env, handleBA, bytes, 0);
    }
    return handleBA;
}



/******************************************
 * NTEventLogger.reportEventNative
 */
JNIEXPORT void JNICALL
Java_com_netscape_osutil_NTEventLogger_reportEventNative
    (JNIEnv *env, jclass clazz, jbyteArray handleBA, jshort type,
    jshort category, jint eventID, jobjectArray jstringArray)
{
    HANDLE logHandle;
    const char **strings=NULL;
    jshort numStrings=0;
    BOOL result;

    assert(env && clazz && handleBA);

    /*
      * Recover the windows HANDLE from the byte array that was passed in
     */
    logHandle = byteArrayToHandle(env, handleBA);
    if( (*env)->ExceptionOccurred(env) ) {
        goto finish;
    }
    assert(logHandle);

    /*
     * convert array of Java strings to array of windows strings
     */
    if( jstringArray ) {
        numStrings = (jshort) (*env)->GetArrayLength(env, jstringArray);
        assert( numStrings > 0 ); /* otherwise why isn't the array NULL? */

        if( numStrings > 0 ) {
            int i;
            jobject obj;

            strings = (char**) malloc(sizeof(char*) * numStrings);

            /* clear this array of pointers so we can goto finish */
            memset((void*)strings, 0, sizeof(char*) * numStrings);

            for(i=0; i < numStrings; i++) {
                obj = (*env)->GetObjectArrayElement(env, jstringArray, i);
                if( obj == NULL ) {
                    assert( (*env)->ExceptionOccurred(env) );
                    goto finish;
                }
                strings[i] = (*env)->GetStringUTFChars(env, obj, NULL);
                if( strings[i] == NULL ) {
                    goto finish;
                }
            }
        }
    }

    /*
     * Report the event
     */
    result = ReportEvent(
        logHandle, 
        type,
        category,
        eventID,
        NULL /* User SID */,
        numStrings,
        0 /* data size */,
        strings,
        NULL /* data */
    );

    /*
     * Throw an exception if the call failed
     */
    if( result == 0 ) {

        int errCode = GetLastError();
        char *errBuf = errCodeToErrMsg(errCode);

        if( errBuf ) {
            throwMsg(env, "java/lang/Exception", errBuf);
            LocalFree(errBuf);
            goto finish;
        } else {
            char buf[200];

            sprintf(buf, "ReportEvent() failed with error code %d", errCode);
            throwMsg(env, "java/lang/Exception", buf);
            goto finish;
        }
    }
        

finish:
    /*    
      * Free the string arrays
     */
    if(strings) {
        int i;
        jobject obj;
        assert(numStrings > 0);
        for( i=0; i < numStrings; i++) {
            obj = (*env)->GetObjectArrayElement(env, jstringArray, i);
            if( obj ) {
                (*env)->ReleaseStringUTFChars(env, obj, strings[i]);
            }
        }
        free((void*)strings);
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_netscape_osutil_NTEventLogger_initNTLog
  (JNIEnv *env, jclass clazz, jstring sourceName)
{
    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    HANDLE logHandle;
    const char *sourceNameChars;
    DWORD errCode;

    assert( env!=NULL && clazz!=NULL && sourceName!=NULL);
    sourceNameChars = (*env)->GetStringUTFChars(env, sourceName, NULL);
    if( sourceNameChars == NULL ) {
        goto finish;
    }

    logHandle = RegisterEventSource( NULL /* localhost */, sourceNameChars );

    if( logHandle == 0 ) {
        /* RegisterEventSource failed. Get an error string, put it in an
         * Exception, and throw it */
        char *errBuf=NULL;

        errCode = GetLastError();
        errBuf = errCodeToErrMsg(errCode);
        if( errBuf ) {
            throwMsg(env, "java/lang/Exception", errBuf);
            LocalFree(errBuf);
            goto finish;
        } else {
            /* FormatMessage failed, create a generic string */
            char buf[200];
            _snprintf(buf, 200, "RegisterEventSource failed with error"
                    " code %d", errCode);
            buf[199] = '\0'; /* ensure it is NULL-terminated */
            throwMsg(env, "java/lang/Exception", buf);
            goto finish;
        }
    }

    /* what to do with handle? return it as a byte array...*/
    handleBA = (*env)->NewByteArray(env, sizeof(HANDLE));
    if(handleBA == NULL ) {
        goto finish;
    }
    handleBytes = (*env)->GetByteArrayElements(env, handleBA, NULL);
    if(handleBytes==NULL) {
        goto finish;
    }
    memcpy(handleBytes, &logHandle, sizeof(logHandle));

finish:
    if(sourceNameChars) {
        (*env)->ReleaseStringUTFChars(env, sourceName, sourceNameChars);
    }
    if(handleBytes) {
        assert(handleBA);
        (*env)->ReleaseByteArrayElements(env, handleBA, handleBytes, 0);
    }
    return handleBA;
}

/**************************************************
 * NTEventLogger.shutdownNTLog
 *
 * Frees the event log handle.
 */
JNIEXPORT void JNICALL
Java_com_netscape_osutil_NTEventLogger_shutdownNTLog
    (JNIEnv* env, jclass clazz, jbyteArray handleBA)
{

    BOOL result;
    HANDLE handle;

    assert(env && clazz && handleBA);

    handle = byteArrayToHandle(env, handleBA);
    if( ! handle ) {
        assert( (*env)->ExceptionOccurred(env) );
        return;
    }

    result = DeregisterEventSource(handle);

    if( result == FALSE ) {
        int errCode = GetLastError();
        char *errBuf;

        errBuf = errCodeToErrMsg(errCode);
        if( errBuf ) {
            throwMsg(env, "java/lang/Exception", errBuf);
            LocalFree(errBuf);
        } else {
            char buf[200];
            sprintf(buf, "DeregisterEventSource failed with code %d", errCode);
            throwMsg(env, "java/lang/Exception", buf);
        }
    }
}

