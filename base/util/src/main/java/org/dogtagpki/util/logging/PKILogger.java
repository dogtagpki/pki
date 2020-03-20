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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.util.logging;

import java.util.HashMap;
import java.util.Map;

public class PKILogger {

    public enum Level {
        ERROR, WARN, INFO, DEBUG, TRACE
    };

    public static Map<Level, java.util.logging.Level> map = new HashMap<>();

    static {
        map.put(Level.ERROR, java.util.logging.Level.SEVERE);
        map.put(Level.WARN, java.util.logging.Level.WARNING);
        map.put(Level.INFO, java.util.logging.Level.INFO);
        map.put(Level.DEBUG, java.util.logging.Level.FINE);
        map.put(Level.TRACE, java.util.logging.Level.FINEST);
    }

    public static void setLevel(Level level) {

        java.util.logging.Level julLevel = map.get(level);

        java.util.logging.Logger.getLogger("org.dogtagpki").setLevel(julLevel);
        java.util.logging.Logger.getLogger("com.netscape").setLevel(julLevel);
        java.util.logging.Logger.getLogger("netscape").setLevel(julLevel);
    }
}
