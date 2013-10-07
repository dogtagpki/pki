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
package com.netscape.cms.authentication;

// java sdk imports.
import java.util.Hashtable;
import java.util.Vector;

/**
 * The structure stores the information of which machine is enabled for
 * the agent-initiated user enrollment, and whom agents enable this feature,
 * and the value of the timeout.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class HashAuthData extends Hashtable<String, Vector<Object>> {

    /**
     *
     */
    private static final long serialVersionUID = -988354133432275910L;
    public static final long TIMEOUT = 600000;
    public static final long LASTLOGIN = 0;

    public HashAuthData() {
    }

    public String getAgentName(String hostname) {
        Vector<Object> val = get(hostname);

        if (val != null)
            return (String) val.elementAt(0);
        return null;
    }

    public void setAgentName(String hostname, String agentName) {
        Vector<Object> val = get(hostname);

        if (val == null) {
            val = new Vector<Object>();
            put(hostname, val);
        }
        val.setElementAt(agentName, 0);
    }

    public long getTimeout(String hostname) {
        Vector<Object> val = get(hostname);

        if (val != null) {
            return ((Long) val.elementAt(1)).longValue();
        }
        return TIMEOUT;
    }

    public void setTimeout(String hostname, long timeout) {
        Vector<Object> val = get(hostname);

        if (val == null) {
            val = new Vector<Object>();
            put(hostname, val);
        }
        val.setElementAt(Long.valueOf(timeout), 1);
    }

    public String getSecret(String hostname) {
        Vector<Object> val = get(hostname);

        if (val != null) {
            return (String) val.elementAt(2);
        }
        return null;
    }

    public void setSecret(String hostname, String secret) {
        Vector<Object> val = get(hostname);

        if (val == null) {
            val = new Vector<Object>();
            put(hostname, val);
        }
        val.setElementAt(secret, 2);
    }

    public long getLastLogin(String hostname) {
        Vector<Object> val = get(hostname);

        if (val != null) {
            return ((Long) val.elementAt(3)).longValue();
        }
        return LASTLOGIN;
    }

    public void setLastLogin(String hostname, long lastLogin) {
        Vector<Object> val = get(hostname);

        if (val == null) {
            val = new Vector<Object>();
            put(hostname, val);
        }
        val.setElementAt(Long.valueOf(lastLogin), 3);
    }
}
