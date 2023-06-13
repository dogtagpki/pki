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

import java.util.EnumMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PKILogger {

    public enum LogLevel {
        ERROR, WARN, INFO, DEBUG, TRACE
    }

    protected static final Map<LogLevel, Level> map = new EnumMap<>(Map.of(
            LogLevel.ERROR, Level.SEVERE,
            LogLevel.WARN, Level.WARNING,
            LogLevel.INFO, Level.INFO,
            LogLevel.DEBUG, Level.FINE,
            LogLevel.TRACE, Level.FINEST));

    public static void setLevel(LogLevel level) {

        Level julLevel = map.get(level);

        Logger.getLogger("org.dogtagpki").setLevel(julLevel);
        Logger.getLogger("com.netscape").setLevel(julLevel);
        Logger.getLogger("netscape").setLevel(julLevel);
    }
}
