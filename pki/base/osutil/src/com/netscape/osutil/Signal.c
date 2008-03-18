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
#include "com_netscape_osutil_Signal.h"
#include "unixdefs.h"
#include <signal.h>
#include <errno.h>

#ifndef MAXSIG
#define MAXSIG 33
#endif

/*
 * These are declared as syncronized funtions in the Java code,
 * so this isn't needed.
 */
#define ENTER_MONITOR /* (*env)->MonitorEnter(obj) */
#define EXIT_MONITOR /* (*env)->MonitorExit(obj) */

typedef struct {
	jobject listener;
	JavaVM *vm;
	int watched;
	int count;
	struct sigaction oact;
} SigWatch;

/* Good thing there's only one signal handler per processes */
static SigWatch sig_watch[MAXSIG];

static void
sig_count(int signo)
{
	JNIEnv *env = NULL;
	jobject listener = NULL;
	jclass listenerClass = NULL;
	jmethodID methodId = NULL;
	jint status;
	JavaVM *vm;
    void *penv;

	sig_watch[signo-1].count++;
	listener = sig_watch[signo-1].listener;
	vm = sig_watch[signo-1].vm;
    
	status = (*vm)->AttachCurrentThread(vm, &penv, NULL);
	if (status != 0) {
		printf("XXX bad attaching\n");
	}
    env = (JNIEnv *)penv;
	listenerClass = (*env)->GetObjectClass(env, listener);
	if (listenerClass == NULL) {
		printf("XXX null listener\n");
	}
	methodId = (*env)->GetMethodID(env, listenerClass,
			"process", "()V");
	if (methodId == NULL) {
		printf("XXX null process\n");
	}
	(*env)->CallVoidMethod(env, listener, methodId);
}

/*
 * Check for a valid signal number.  Throw IllegalArgumentException if so.
 * This really shouldn't happen since the Java code protects us.
 */
static int 
valid_signo(JNIEnv *env, int signo)
{
	jclass illExc;

	if (signo <= MAXSIG && signo > 0)
		return 1;

	illExc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
	if (illExc == 0) /* Unable to find the new exception class, give up. */
		return 0;
	(*env)->ThrowNew(env, illExc, "bad signal number");
	return 0;
}

/**
 * Associates callback with signal. This obsoletes all
 * the functions below.
 */
JNIEXPORT void JNICALL 
Java_com_netscape_osutil_Signal_addSignalListener(JNIEnv *env, 
	jclass cls, jint signo, jobject listener) 
{
	struct sigaction act;
	SigWatch *sw;
	JavaVM *vmBuf[1];
#if 0
	jsize nVMs;
#endif
	

	if (!valid_signo(env, signo))
		return;

	sw = &sig_watch[signo-1];

	if (sw->watched) {
		EXIT_MONITOR
		return;  /* Already being watched */
	}

	sw->watched = 1;
	sw->listener = (*env)->NewGlobalRef(env, listener);
#if 0
    /* IBM JRE1.5 does not like this, and I dont think we
       are using this file anyway. So I've commented this out */
	JNI_GetCreatedJavaVMs(vmBuf, 1, &nVMs);
#endif
	sw->vm = vmBuf[0];

	sw->count = 0;
	act.sa_flags = SA_RESTART;
	sigemptyset(&act.sa_mask);
	act.sa_handler = sig_count;
	sigaction(signo, &act, &sw->oact);

	EXIT_MONITOR
}

/*
 * Class:     com_netscape_osutil_Signal
 * Method:    watch
 * Signature: (I)V
 *
 * Add a signal handler to count the number of signals recieved.
 *
 */
JNIEXPORT void JNICALL 
Java_com_netscape_osutil_Signal_watch(JNIEnv *env, jclass cls, 
	jint signo)
{
	struct sigaction act;
	SigWatch *sw;

	if (!valid_signo(env, signo))
		return;

	sw = &sig_watch[signo-1];

	if (sw->watched) {
		EXIT_MONITOR
		return;  /* Already being watched */
	}

	sw->watched = 1;
	sw->listener = NULL;
	sw->vm = NULL;

	sw->count = 0;
	act.sa_flags = SA_RESTART;
	sigemptyset(&act.sa_mask);
	act.sa_handler = sig_count;
	sigaction(signo, &act, &sw->oact);

	EXIT_MONITOR

}


/*
 * Class:     com_netscape_certsrv_unix_Signal
 * Method:    release
 * Signature: (I)V
 *
 * Restore whatever signal handler was present before the watch call.
 */
JNIEXPORT void JNICALL 
Java_com_netscape_osutil_Signal_release(JNIEnv *env, jclass cls, 
	jint signo)
{
	SigWatch *sw;

	if (!valid_signo(env, signo))
		return;

	sw = &sig_watch[signo-1];

	ENTER_MONITOR

	if (!sw->watched) {
		EXIT_MONITOR
		return;  /* not being watched */
	}

	sw->watched = 0;
	sw->count = 0;
	sigaction(signo, &sw->oact, NULL);

	EXIT_MONITOR
}

/*
 * Class:     com_netscape_certsrv_unix_Signal
 * Method:    caught
 * Signature: (I)I
 *
 * Return the number of signals caught.  Resets the count to 0
 */
JNIEXPORT jint JNICALL 
Java_com_netscape_osutil_Signal_caught(JNIEnv *env, jclass cls, 
	jint signo)
{
	int count;
	SigWatch *sw;

	if (!valid_signo(env, signo))
		return 0;

	sw = &sig_watch[signo-1];

	if (!sw->watched) {
		return 0;  /* not being watched */
	}

	/*
	 * The usefulness of multiple threads using this interface
	 * is questionable.  This just guarantees some consistency
	 */
	ENTER_MONITOR
	count = sw->count;
	sw->count = 0;
	EXIT_MONITOR

	return count;
}

/*
 * Class:     com_netscape_certsrv_unix_Signal
 * Method:    send
 * Signature: (II)I
 *
 * Send a signal to a process
 */
JNIEXPORT void JNICALL 
Java_com_netscape_osutil_Signal_send(JNIEnv *env, jclass cls, jint pid,
	jint signo)
{
	valid_signo(env, signo);
	if (kill(pid, signo) != 0) {
		switch (errno) {
		case EINVAL:
			unix_throw_exception(env, ILLARG, "invalid signal");
			break;
		case EPERM:
			unix_throw_exception(env, SECURITY, "permission denied");
			break;
		} 
	}
}


