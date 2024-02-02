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

import com.netscape.cmscore.base.ConfigStore;

public class Debug {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Debug.class);

    public final static String ID = "debug";
    public final static String PROP_LEVEL = "level";

    public static final int OBNOXIOUS = 1;
    public static final int VERBOSE = 5;
    public static final int INFORM = 10;
    public static final int WARN = 15;

    private static char getNybble(byte b) {
        return b < 10 ? (char)('0' + b) : (char)('a' + b - 10);
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

        PKILogger.LogLevel logLevel;

        if (level <= OBNOXIOUS) {
            logLevel = PKILogger.LogLevel.TRACE;

        } else if (level <= VERBOSE) {
            logLevel = PKILogger.LogLevel.DEBUG;

        } else if (level <= INFORM) {
            logLevel = PKILogger.LogLevel.INFO;

        } else if (level <= WARN) {
            logLevel = PKILogger.LogLevel.WARN;

        } else {
            logLevel = PKILogger.LogLevel.ERROR;
        }

        PKILogger.setLevel(logLevel);
    }

    /**
     * Debug subsystem initialization. This subsystem is usually
     * given the following parameters:
     */
    public void init(ConfigStore config) throws Exception {

        int level = config.getInteger(PROP_LEVEL, INFORM);
        setLevel(level);

        logger.debug("============================================");
        logger.debug("=====  DEBUG SUBSYSTEM INITIALIZED   =======");
        logger.debug("============================================");

        logger.info("OS name: " + System.getProperty("os.name"));
        logger.info("OS version: " + System.getProperty("os.version"));
        logger.info("OS arch: " + System.getProperty("os.arch"));

        logger.info("Java vendor: " + System.getProperty("java.vendor"));
        logger.info("Java version: " + System.getProperty("java.version"));
        logger.info("Java home: " + System.getProperty("java.home"));

        logger.info("Catalina base: " + System.getProperty("catalina.base"));
    }
}
