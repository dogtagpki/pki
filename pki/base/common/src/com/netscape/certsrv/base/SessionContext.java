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


import java.util.*;


/**
 * This class specifies the context object that includes
 * authentication environment and connection information.
 * This object is later used in access control evaluation.
 * This is a global object that can be accessible 
 * throughout the server. It is useful for passing 
 * global and per-thread infomration in methods.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class SessionContext extends Hashtable implements IAuthInfo {

    /**
     * End user locale of the current processing request in the current thread.
     */
    public static final String LOCALE = "locale"; // Locale

    /**
     * Authentication token in the current thread.
     */
    public static final String AUTH_TOKEN = "AuthToken"; // IAuthToken

    /**
     * ID of the authentication manager in the current thread.
     */
    public static final String AUTH_MANAGER_ID = "authManagerId"; // String

    /**
     * User object of the authenticated user in the current thread.
     */
    public static final String USER = "user"; // IUser

    /**
     * User ID of the authenticated user in the current thread.
     */
    public static final String USER_ID = "userid"; // String

    /**
     * Group ID of the authenticated user in the current thread.
     */
    public static final String GROUP_ID = "groupid"; //String

    /**
     * ID of the processing request in the current thread.
     */
    public static final String REQUESTER_ID = "requesterID"; // String

    /**
     * Recovery ID of a recovery operation in KRA in the current thread.
     */
    public static final String RECOVERY_ID = "recoveryID"; // String

    /**
     * IP Address of the requestor of the request in the current thread.
     */
    public static final String IPADDRESS = "ipAddress";

    private static Hashtable mContexts = new Hashtable();

    /**
     * Constructs a session context.
     */
    public SessionContext() {
        super();
    }

    /**
     * Creates a new context and associates it with
     * the current thread. If the current thread is
     * also associated with a old context, the old
     * context will be replaced.
     */
    private static SessionContext createContext() {
        SessionContext sc = new SessionContext();

        setContext(sc);
        return sc;
    }

    /**
     * Sets the current context. This allows the 
     * caller to associate a specific session context 
     * with the current thread.
     * This methods makes custom session context
     * possible.
     *
     * @param sc session context
     */
    public static void setContext(SessionContext sc) {
        mContexts.put(Thread.currentThread(), sc);
    }

    /**
     * Retrieves the session context associated with 
     * the current thread. If no context is associated,
     * a context is created.
     *
     * @return sesssion context
     */
    public static SessionContext getContext() {
        SessionContext sc = (SessionContext) mContexts.get(
                Thread.currentThread());

        if (sc == null) {
            sc = createContext();
        }
        return sc;
    }

    /**
     * Retrieves the session context associated with 
     * the current thread. If no context is associated,
     * null is returned.
     *
     * @return sesssion context
     */
    public static SessionContext getExistingContext() {
        SessionContext sc = (SessionContext)
            mContexts.get(Thread.currentThread());

        if (sc == null) {
            return null;
        }

        return sc;
    }

    /**
     * Releases the current session context.
     */
    public static void releaseContext() {
        SessionContext sc = (SessionContext) mContexts.get(
                Thread.currentThread());

        if (sc != null) {
            mContexts.remove(Thread.currentThread());
        }
    }
}
