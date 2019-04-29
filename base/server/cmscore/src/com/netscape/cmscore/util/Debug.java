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

import org.dogtagpki.util.logging.PKILogger;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.cmscore.apps.CMS;

public class Debug
        implements ISubsystem {

    private static Debug mInstance = new Debug();

    public static final int OBNOXIOUS = 1;
    public static final int VERBOSE = 5;
    public static final int INFORM = 10;
    public static final int WARN = 15;

    private static char getNybble(byte b) {
        if (b < 10) {
            return (char)('0' + b);
        } else {
            return (char)('a' + b - 10);
        }
    }

    public static String dump(byte[] b) {

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < b.length; i++) {
            sb.append(getNybble((byte) ((b[i] & 0xf0) >> 4)));
            sb.append(getNybble((byte) (b[i] & 0x0f)));

            if (((i % 16) == 15) && i != b.length) {
                sb.append('\n');
            } else {
                sb.append(" ");
            }
        }

        return sb.toString();
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

        PKILogger.Level logLevel;

        if (level <= OBNOXIOUS) {
            logLevel = PKILogger.Level.TRACE;

        } else if (level <= VERBOSE) {
            logLevel = PKILogger.Level.DEBUG;

        } else if (level <= INFORM) {
            logLevel = PKILogger.Level.INFO;

        } else if (level <= WARN) {
            logLevel = PKILogger.Level.WARN;

        } else {
            logLevel = PKILogger.Level.ERROR;
        }

        PKILogger.setLevel(logLevel);
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

    private static final String PROP_LEVEL = "level";

    /**
     * Debug subsystem initialization. This subsystem is usually
     * given the following parameters:
     */
    public void init(ISubsystem owner, IConfigStore config) {
        mConfig = config;

        try {
            int level = mConfig.getInteger(PROP_LEVEL, VERBOSE);
            setLevel(level);

            CMS.logger.debug("============================================");
            CMS.logger.debug("=====  DEBUG SUBSYSTEM INITIALIZED   =======");
            CMS.logger.debug("============================================");

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
