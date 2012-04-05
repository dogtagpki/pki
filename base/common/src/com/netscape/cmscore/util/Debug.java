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
package com.netscape.cmscore.util;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Hashtable;
import java.util.StringTokenizer;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.cmsutil.util.Utils;

public class Debug
        implements ISubsystem {

    private static Debug mInstance = new Debug();
    private static boolean mShowCaller = false;

    /* This dateformatter is used to put the date on each
       debug line. But the DateFormatter is not thread safe,
       so I create a thread-local DateFormatter for each thread
     */
    private static String DATE_PATTERN = "dd/MMM/yyyy:HH:mm:ss";
    private static ThreadLocal<SimpleDateFormat> mFormatObject = new ThreadLocal<SimpleDateFormat>() {
        protected synchronized SimpleDateFormat initialValue() {
            return new SimpleDateFormat(DATE_PATTERN);
        }
    };

    /* the dateformatter should be accessed with this function */
    private static SimpleDateFormat getDateFormatter() {
        return mFormatObject.get();
    }

    public static final boolean ON = false;
    public static final int OBNOXIOUS = 10;
    public static final int VERBOSE = 5;
    public static final int INFORM = 1;

    // the difference between this and 'ON' is that this is always
    // guaranteed to log to 'mOut', whereas other parts of the server
    // may do:
    //  if (Debug.ON) {
    //     System.out.println("..");
    //	}
    // I want to make sure that any Debug.trace() is not logged to
    // System.out if the server is running under watchdog

    private static boolean TRACE_ON = false;

    private static int mDebugLevel = VERBOSE;

    private static PrintStream mOut = null;
    private static Hashtable<String, String> mHK = null;

    static {
        if (TRACE_ON == true) {
            mOut = System.out;
        }
    }

    public static void trace(int level, String t) {
        trace(level, t, null, true);
    }

    /**
     * Output a debug message at the output stream sepcified in the init()
     * method. This method is very lightweight if debugging is turned off, since
     * it will return immediately. However, the caller should be aware that
     * if the argument to Debug.trace() is an object whose toString() is
     * expensive, that this toString() will still be called in any case.
     * In such a case, it is wise to wrap the Debug.trace like this:
     *
     * <pre>
     * if (Debug.on()) {
     *     Debug.trace(&quot;obj is: &quot; + obj);
     * }
     * </pre>
     *
     * @param level the message level. If this is >= than the currently set
     *            level (set with setLevel() ), the message is printed
     * @param t the message to print
     * @param ignoreStack when walking the stack to determine the
     *            location of the method that called the trace() method,
     *            ignore any classes with this string in. Can be null
     * @param printCaller if true, (and if static mShowCaller is true)
     *            dump caller information in this format:
     *            (source-file:line) methodname():
     */
    public static void trace(int level, String t, String ignoreStack, boolean printCaller) {
        String callerinfo = "";
        if (!TRACE_ON)
            return;
        if (level >= mDebugLevel) {
            if (mShowCaller && printCaller) {
                String method = "";
                String fileAndLine = "";

                try {
                    Throwable tr = new Throwable();
                    StackTraceElement ste[] = tr.getStackTrace();
                    int i = 0;
                    while ((i < ste.length) &&
                            (ste[i].getMethodName().toLowerCase().indexOf("debug") > -1) ||
                            (ste[i].getMethodName().toLowerCase().indexOf("hashkey") > -1) ||
                            (ste[i].getClassName().toLowerCase().indexOf("propconfigstore") > -1) ||
                            (ste[i].getClassName().toLowerCase().indexOf("argblock") > -1) ||
                            (ste[i].getClassName().toLowerCase().indexOf("debug") > -1) ||
                            (ste[i].getMethodName().toLowerCase().indexOf("trace") > -1))
                        i++;

                    if (i < ste.length) {
                        fileAndLine = ste[i].getFileName() + ":" +
                                ste[i].getLineNumber();
                        method = ste[i].getMethodName() + "()";
                    }

                    callerinfo = fileAndLine + ":" + method + " ";
                } catch (Exception f) {
                }
            }

            outputTraceMessage(callerinfo + t);
        }
    }

    private static void outputTraceMessage(String t) {
        if (!TRACE_ON)
            return;
        SimpleDateFormat d = getDateFormatter();
        if (mOut != null && d != null) {
            mOut.println("[" + d.format(new Date()) + "][" + Thread.currentThread().getName() + "]: " + t);
            mOut.flush();
        }
    }

    private static boolean hkdotype(String type) {
        if (mHK != null && mHK.get(type) != null) {
            return true;
        } else {
            return false;
        }
    }

    public static void traceHashKey(String type, String key) {
        if (hkdotype(type)) {
            trace("GET r=" + type + ",k=" + key);
        }
    }

    public static void traceHashKey(String type, String key, String val) {
        if (hkdotype(type)) {
            trace("GET r=" + type + ",k=" + key + ",v=" + val);
        }
    }

    public static void traceHashKey(String type, String key, String val, String def) {
        if (hkdotype(type)) {
            trace("GET r=" + type + ",k=" +
                     key + ",v=" + val + ",d=" + def);
        }
    }

    public static void putHashKey(String type, String key, String value) {
        if (hkdotype(type)) {
            outputTraceMessage("PUT r=" + type + ",k=" + key + ",v=" + value);
        }
    }

    public static void trace(String t) {
        trace(VERBOSE, t);
    }

    public static void print(int level, String t) {
        if (!TRACE_ON)
            return;
        if (mOut != null) {
            if (level >= mDebugLevel)
                mOut.print(t);
        }
    }

    public static void print(String t) {
        print(VERBOSE, t);
    }

    private static void printNybble(byte b) {
        if (mOut == null)
            return;
        if (b < 10)
            mOut.write('0' + b);
        else
            mOut.write('a' + b - 10);
    }

    /**
     * If tracing enabled, dump a byte array to debugging printstream
     * as hex, colon-seperated bytes, 16 bytes to a line
     */
    public static void print(byte[] b) {
        if (!TRACE_ON)
            return;
        if (mOut == null)
            return;

        for (int i = 0; i < b.length; i++) {
            printNybble((byte) ((b[i] & 0xf0) >> 4));
            printNybble((byte) (b[i] & 0x0f));
            mOut.print(" ");
            if (((i % 16) == 15) && i != b.length)
                mOut.println("");
        }
        mOut.println("");
        mOut.flush();
    }

    /**
     * Print the current stack trace to the debug printstream
     */
    public static void printStackTrace() {
        if (!TRACE_ON)
            return;
        Exception e = new Exception("Debug");

        printStackTrace(e);
    }

    /**
     * Print the stack trace of the named exception
     * to the debug printstream
     */
    public static void printStackTrace(Throwable e) {
        if (!TRACE_ON)
            return;
        if (mOut == null)
            return;

        e.printStackTrace(mOut);
    }

    /**
     * Set the current debugging level. You can use:
     *
     * <pre>
     * OBNOXIOUS = 10
     * VERBOSE   = 5
     * INFORM    = 1
     * </pre>
     *
     * Or another value
     */

    public static void setLevel(int level) {
        mDebugLevel = level;
    }

    public static int getLevel(int level) {
        return mDebugLevel;
    }

    /**
     * Test if debugging is on. Do NOT write to System.out in your debug code
     */
    public static boolean on() {
        return TRACE_ON;
    }

    /*  ISubsystem methods: */

    public static String ID = "debug";
    private static IConfigStore mConfig = null;

    public String getId() {
        return ID;
    }

    public void setId(String id) {
        ID = id;
    }

    private static final String PROP_ENABLED = "enabled";
    private static final String PROP_FILENAME = "filename";
    private static final String PROP_HASHKEYS = "hashkeytypes";
    private static final String PROP_SHOWCALLER = "showcaller";
    private static final String PROP_LEVEL = "level";
    private static final String PROP_APPEND = "append";

    /**
     * Debug subsystem initialization. This subsystem is usually
     * given the following parameters:
     *
     * <pre>
     * debug.enabled   : (true|false) default false
     * debug.filename  : can be a pathname, or STDOUT
     * debug.hashkeytypes: comma-separated list of hashkey types
     *    possible values:  "CS.cfg"
     * debug.showcaller: (true|false) default false  [show caller method name for Debug.trace()]
     * </pre>
     */
    public void init(ISubsystem owner, IConfigStore config) {
        mConfig = config;
        String filename = null;
        String hashkeytypes = null;
        boolean append = true;

        try {
            TRACE_ON = mConfig.getBoolean(PROP_ENABLED, false);
            if (TRACE_ON) {
                filename = mConfig.getString(PROP_FILENAME, null);
                if (filename == null) {
                    TRACE_ON = false;
                }
                hashkeytypes = mConfig.getString(PROP_HASHKEYS, null);
                mShowCaller = mConfig.getBoolean(PROP_SHOWCALLER, false);
                append = mConfig.getBoolean(PROP_APPEND, true);
            }
            if (TRACE_ON) {
                if (filename.equals("STDOUT")) {
                    mOut = System.out;
                } else {
                    if (!Utils.isNT()) {
                        // Always insure that a physical file exists!
                        Utils.exec("touch " + filename);
                        Utils.exec("chmod 00640 " + filename);
                    }
                    OutputStream os = new FileOutputStream(filename, append);
                    mOut = new PrintStream(os, true); /* true == autoflush */
                }
                if (hashkeytypes != null) {
                    StringTokenizer st = new StringTokenizer(hashkeytypes,
                            ",", false);
                    mHK = new Hashtable<String, String>();
                    while (st.hasMoreElements()) {
                        String hkr = st.nextToken();
                        mHK.put(hkr, "true");
                    }
                }
            }
            outputTraceMessage("============================================");
            outputTraceMessage("=====  DEBUG SUBSYSTEM INITIALIZED   =======");
            outputTraceMessage("============================================");
            int level = mConfig.getInteger(PROP_LEVEL, VERBOSE);
            setLevel(level);
        } catch (Exception e) {
            // Don't do anything. Logging is not set up yet, and
            // we can't write to STDOUT.
        }
    }

    public void startup() {
    }

    public void shutdown() {
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    // for singleton

    public static Debug getInstance() {
        return mInstance;
    }

}
