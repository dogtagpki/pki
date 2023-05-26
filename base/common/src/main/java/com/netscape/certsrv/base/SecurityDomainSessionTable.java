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
package com.netscape.certsrv.base;

import java.util.Enumeration;

/**
 * This class defines the abstraction for the cookie table.
 **/
public abstract class SecurityDomainSessionTable {

    public static final int SUCCESS = 0;
    public static final int FAILURE = 1;

    protected long timeToLive;

    public abstract void addEntry(String sessionID, String ip, String uid, String group) throws Exception;

    public abstract int removeEntry(String sessionID) throws Exception;

    public abstract boolean sessionExists(String sessionID) throws Exception;

    public abstract String getIP(String sessionID) throws Exception;

    public abstract String getUID(String sessionID) throws Exception;

    public abstract String getGroup(String sessionID) throws Exception;

    public abstract long getBeginTime(String sessionID) throws Exception;

    public abstract int getSize() throws Exception;

    public long getTimeToLive() {
        return timeToLive;
    }

    public abstract Enumeration<String> getSessionIDs() throws Exception;

    public abstract void shutdown();
}
