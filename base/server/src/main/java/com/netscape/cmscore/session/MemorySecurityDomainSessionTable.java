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
package com.netscape.cmscore.session;

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.SecurityDomainSessionTable;

/**
 * This object stores the values for IP, uid and group based on the cookie id.
 */
public class MemorySecurityDomainSessionTable
        extends SecurityDomainSessionTable {

    private Hashtable<String, Vector<Comparable<?>>> m_sessions;
    private long m_timeToLive;

    public MemorySecurityDomainSessionTable(long timeToLive) {
        m_sessions = new Hashtable<>();
        m_timeToLive = timeToLive;
    }

    @Override
    public int addEntry(String sessionId, String ip,
            String uid, String group) {
        Vector<Comparable<?>> v = new Vector<>();
        v.addElement(ip);
        v.addElement(uid);
        v.addElement(group);
        Date d = new Date();
        long t = d.getTime();
        v.addElement(Long.valueOf(t));
        m_sessions.put(sessionId, v);
        return SUCCESS;
    }

    @Override
    public int removeEntry(String sessionId) {
        m_sessions.remove(sessionId);
        return SUCCESS;
    }

    @Override
    public boolean sessionExists(String sessionId) {
        return m_sessions.containsKey(sessionId);
    }

    @Override
    public Enumeration<String> getSessionIDs() {
        return m_sessions.keys();
    }

    @Override
    public String getIP(String sessionId) {
        Vector<Comparable<?>> v = m_sessions.get(sessionId);
        if (v != null)
            return (String) v.elementAt(0);
        return null;
    }

    @Override
    public String getUID(String sessionId) {
        Vector<Comparable<?>> v = m_sessions.get(sessionId);
        if (v != null)
            return (String) v.elementAt(1);
        return null;
    }

    @Override
    public String getGroup(String sessionId) {
        Vector<Comparable<?>> v = m_sessions.get(sessionId);
        if (v != null)
            return (String) v.elementAt(2);
        return null;
    }

    @Override
    public long getBeginTime(String sessionId) {
        Vector<Comparable<?>> v = m_sessions.get(sessionId);
        if (v != null) {
            Long n = (Long) v.elementAt(3);
            if (n != null)
                return n.longValue();
        }
        return -1;
    }

    @Override
    public long getTimeToLive() {
        return m_timeToLive;
    }

    @Override
    public int getSize() {
        return m_sessions.size();
    }

    @Override
    public void shutdown() {
    }
}
