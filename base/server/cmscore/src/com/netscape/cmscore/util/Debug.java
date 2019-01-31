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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Hashtable;
import java.util.StringTokenizer;

import org.dogtagpki.util.logging.PKILogger;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;

public class Debug
        implements ISubsystem {

    private static Debug mInstance = new Debug();

    public static final boolean ON = false;
    public static final int OBNOXIOUS = 1;
    public static final int VERBOSE = 5;
    public static final int INFORM = 10;

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

    private static Hashtable<String, String> mHK = null;

    public static void trace(int level, String t) {
        if (!TRACE_ON)
            return;

        if (level <= OBNOXIOUS) {
            CMS.logger.trace(t);

        } else if (level <= VERBOSE) {
            CMS.logger.debug(t);

        } else if (level <= INFORM) {
            CMS.logger.info(t);

        } else {
            CMS.logger.warn(t);
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
            trace("PUT r=" + type + ",k=" + key + ",v=" + value);
        }
    }

    public static void trace(String t) {
        trace(VERBOSE, t);
    }

    public static void print(int level, String t) {
        trace(level, t);
    }

    public static void print(String t) {
        print(VERBOSE, t);
    }

    private static char getNybble(byte b) {
        if (b < 10) {
            return (char)('0' + b);
        } else {
            return (char)('a' + b - 10);
        }
    }

    /**
     * If tracing enabled, dump a byte array to debugging printstream
     * as hex, colon-seperated bytes, 16 bytes to a line
     */
    public static void print(byte[] b) {
        if (!TRACE_ON)
            return;

        String s = dump(b);
        if (s.length() > 0) {
            CMS.logger.debug(s);
        }
    }

    public static String dump(byte[] b) {

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < b.length; i++) {
            sb.append(getNybble((byte) ((b[i] & 0xf0) >> 4)));
            sb.append(getNybble((byte) (b[i] & 0x0f)));
            sb.append(" ");

            if (((i % 16) == 15) && i != b.length) {
                CMS.logger.debug(sb.toString());
                sb = new StringBuilder();
            }
        }

        return sb.toString();
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

        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        // If the exception does not have a message, the stack trace will
        // show the exception class name.
        //
        // However, if the exception has a message, the stack trace will
        // only show the message. To help troubleshooting, the class name
        // is prepended to the message.

        if (e.getMessage() != null) {
            pw.print(e.getClass().getName());
            pw.print(": ");
        }

        e.printStackTrace(pw);

        CMS.logger.warn(sw.toString());
    }

    /**
     * Set the current debugging level. You can use:
     *
     * <pre>
     * OBNOXIOUS = 1
     * VERBOSE   = 5
     * INFORM    = 10
     * </pre>
     *
     * Or another value
     */

    public static void setLevel(int level) {
        mDebugLevel = level;

        PKILogger.Level logLevel;

        if (level <= OBNOXIOUS) {
            logLevel = PKILogger.Level.TRACE;

        } else if (level <= VERBOSE) {
            logLevel = PKILogger.Level.DEBUG;

        } else if (level <= INFORM) {
            logLevel = PKILogger.Level.INFO;

        } else {
            logLevel = PKILogger.Level.WARN;
        }

        PKILogger.setLevel(logLevel);
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
    private static final String PROP_LEVEL = "level";

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

        try {
            TRACE_ON = mConfig.getBoolean(PROP_ENABLED, false);
            if (TRACE_ON) {
                filename = mConfig.getString(PROP_FILENAME, null);
                if (filename == null) {
                    TRACE_ON = false;
                }
                hashkeytypes = mConfig.getString(PROP_HASHKEYS, null);
            }
            if (TRACE_ON) {
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
            trace("============================================");
            trace("=====  DEBUG SUBSYSTEM INITIALIZED   =======");
            trace("============================================");
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
