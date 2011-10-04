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
package com.netscape.osutil;


import java.io.*;


/**
 * This class is a very simpy Java wrapper around Posix/Unix signals.
 * The interface allows the programmer to catch a signal and check to
 * see how many times the signal has been recieved.
 */

public class Signal {

    /** hangup */
    public static final SignalNo SIGHUP = new SignalNo(1);

    /** interrupt (rubout) */
    public static final SignalNo SIGINT = new SignalNo(2);

    /** quit (ASCII FS) */
    public static final SignalNo SIGQUIT = new SignalNo(3);

    /** illegal instruction (not reset when caught) */
    public static final SignalNo SIGILL = new SignalNo(4);

    /** trace trap (not reset when caught) */
    public static final SignalNo SIGTRAP = new SignalNo(5);

    /** IOT instruction */
    public static final SignalNo SIGIOT = new SignalNo(6);

    /** used by abort, replace SIGIOT in the future */
    public static final SignalNo SIGABRT = SIGIOT;

    /** EMT instruction */
    public static final SignalNo SIGEMT = new SignalNo(7);

    /** floating point exception */
    public static final SignalNo SIGFPE = new SignalNo(8);

    /** kill (cannot be caught or ignored) */
    public static final SignalNo SIGKILL = new SignalNo(9);

    /** bus error */
    public static final SignalNo SIGBUS = new SignalNo(10);

    /** segmentation violation */
    public static final SignalNo SIGSEGV = new SignalNo(11);

    /** bad argument to system call */
    public static final SignalNo SIGSYS = new SignalNo(12);

    /** write on a pipe with no one to read it */
    public static final SignalNo SIGPIPE = new SignalNo(13);

    /** alarm clock */
    public static final SignalNo SIGALRM = new SignalNo(14);

    /** software termination signal from kill */
    public static final SignalNo SIGTERM = new SignalNo(15);

    /** user defined signal 1 */
    public static final SignalNo SIGUSR1 = new SignalNo(16);

    /** user defined signal 2 */
    public static final SignalNo SIGUSR2 = new SignalNo(17);

    /** death of a child */
    public static final SignalNo SIGCLD = new SignalNo(18);

    /** compatibility */
    public static final SignalNo SIGCHLD = SIGCLD;

    /** power-fail restart */
    public static final SignalNo SIGPWR = new SignalNo(19);

    /** window change */
    public static final SignalNo SIGWINCH = new SignalNo(20);

    /** urgent socket condition */
    public static final SignalNo SIGURG = new SignalNo(21);

    /** pollable event occurred */
    public static final SignalNo SIGPOLL = new SignalNo(22);

    /** sendable stop signal not from tty */
    public static final SignalNo SIGSTOP = new SignalNo(23);

    /** stop signal from tty */
    public static final SignalNo SIGTSTP = new SignalNo(24);

    /** continue a stopped process */
    public static final SignalNo SIGCONT = new SignalNo(25);

    /** to readers pgrp upon background tty read */
    public static final SignalNo SIGTTIN = new SignalNo(26);

    /** like TTIN for output if tp->t_local&TOSTOP */
    public static final SignalNo SIGTTOU = new SignalNo(27);

    /** virtual timer alarm */
    public static final SignalNo SIGVTALRM = new SignalNo(28);

    /** profile alarm */
    public static final SignalNo SIGPROF = new SignalNo(29);

    /** CPU time limit exceeded */
    public static final SignalNo SIGXCPU = new SignalNo(30);

    /** File size limit exceeded */
    public static final SignalNo SIGXFSZ = new SignalNo(31);

    /** process's lwps are blocked */
    public static final SignalNo SIGWAITING = new SignalNo(32);

    /** special signal used by thread library */
    public static final SignalNo SIGLWP = new SignalNo(33);
    // Once you get past SIGLWP, it's not portable between OS's

    /**
     * Watch a specific signal 
     *
     * @param signo The signal which you want to catch
     */
    // catch is a reserved word!
    public static void watch(SignalNo signo) {
        // Passing ints makes JNI much easier
        watch(signo.toInt());
    }

    synchronized private static native void watch(int signo);

    public static void addSignalListener(SignalNo signo, SignalListener l) {
        addSignalListener(signo.toInt(), l);
    }

    synchronized private static native void addSignalListener(int signo,
        SignalListener l);

    /**
     * Stop checking for a specific signal
     *
     * @param signo The signal which you no longer want to catch
     */
    public static void release(SignalNo signo) {
        release(signo.toInt());
    }

    synchronized private static native void release(int signo);

    /**
     * See how many times a specific signal has be caught
     *
     * @param signo The signal which you are watching
     */
    public static int caught(SignalNo signo) {
        return caught(signo.toInt());
    }

    synchronized private static native int caught(int signo);

    /**
     * Send a signal to a pid
     *
     * @param signo The signal which you are sending
     */
    public static void send(int pid, SignalNo signo) {
        send(pid, signo.toInt());
    }

    synchronized private static native void send(int pid, int signo);

    static {
        boolean mNativeLibrariesLoaded = false;
        if (File.separatorChar == '/') {
            String os = System.getProperty( "os.name" );
            if( ( os.equals( "Linux" ) ) ) {
                // Check for 64-bit library availability
                // prior to 32-bit library availability.
                mNativeLibrariesLoaded =
                    OSUtil.tryLoad( "/usr/lib64/osutil/libosutil.so" );
                if( mNativeLibrariesLoaded ) {
                    System.out.println( "64-bit osutil library loaded" );
                } else {
                    // REMINDER:  May be trying to run a 32-bit app
                    //            on 64-bit platform.
                    mNativeLibrariesLoaded =
                        OSUtil.tryLoad( "/usr/lib/osutil/libosutil.so" );
                    if( mNativeLibrariesLoaded ) {
                        System.out.println( "32-bit osutil library loaded");
                    } else {
                        System.out.println( "FAILED loading osutil library!");
                        System.exit( -1 );
                    }
                }
            } else {
                try {
                    System.loadLibrary( "osutil" );
                    System.out.println( "osutil library loaded" );
                    mNativeLibrariesLoaded = true;
                } catch( Throwable t ) {
                    // This is bad news, the program is doomed at this point
                    t.printStackTrace();
                }
            }
        }
    }

}


/**
 * This class implements an enumerated type for signal values.  It's hidden
 * from users who must use the static values defined in the Signal class.
 */
class SignalNo {
    private int mSignalNumber = 0;

    /**
     * Construct a SignalNo from an integer
     */
    public SignalNo(int signo) {
        mSignalNumber = signo;
    }

    /**
     * Return the integer equivalent of a signal
     */
    public int toInt() {
        return mSignalNumber;
    }
}
