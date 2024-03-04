/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/

package com.netscape.management.client.console;

import java.applet.Applet;
import java.util.Enumeration;
import java.util.Hashtable;

import javax.swing.JFrame;

import com.netscape.management.client.util.Debug;

import netscape.ldap.LDAPConnection;


/**
 * Contains session information such as the directory server
 * host, port, and base DN used for authentication, as well
 * as information for the authenticated user such as the
 * username and password.
 *
 * @author  Terence Kwan (terencek@netscape.com)
 */
public class ConsoleInfo extends Hashtable {
    // internal static string
    public static final String KEY_HOST = "Host";
    public static final String KEY_PORT = "Port";
    public static final String KEY_USER_HOST = "UserHost";
    public static final String KEY_USER_PORT = "UserPort";
    public static final String KEY_AUTHENTICATION_DN = "AuthenticationDN";
    public static final String KEY_AUTHENTICATION_PASSWORD = "AuthenticationPassword";
    public static final String KEY_BASE_DN = "BaseDN";
    public static final String KEY_USER_BASE_DN = "UserBaseDN";
    public static final String KEY_LDAP_CONNECTION = "LDAPConnection";
    public static final String KEY_USER_LDAP_CONNECTION = "UserLDAPConnection";
    public static final String KEY_CURRENT_DN = "CurrentDN";
    public static final String KEY_ADMIN_URL = "AdminDN";
    public static final String KEY_ADMIN_OS = "AdminOS";
    public static final String KEY_ACL_DN = "AclDN";
    public static final String KEY_USER_GROUP_DN = "UserGroupDN";
    public static final String KEY_APPLET = "Applet";
    public static final String KEY_AUTH_VALUES = "AuthValues";
    public static final String KEY_USER_PREFERENCE_DN = "UserPreferenceDN";

    public static JFrame frame = null; // global frame


    /**
     * Constructor creates a new ConsoleInfo object.
     */
    public ConsoleInfo() {
    }


    /**
      * Constructor creates a new ConsoleInfo object with authentication
      * information.
      *
      * @param host          the directory server host name
      * @param port          the directory server port number
      * @param authDN        the user ID
      * @param authPassword  the user password
      * @param baseDN        the base DN
      */
    public ConsoleInfo(String host, int port, String authDN,
            String authPassword, String baseDN) {
        setHost(host);
        setPort(port);
        setAuthenticationDN(authDN);
        setAuthenticationPassword(authPassword);
        setBaseDN(baseDN);
    }


    /**
      * Sets the directory server host name.
      *
      * @param host  the directory server host name
      */
    public void setHost(String host) {
        put(KEY_HOST, host);
    }


    /**
      * Returns the directory server host name.
      *
      * @return  the directory server host name
      */
    public String getHost() {
        return (String) get(KEY_HOST);
    }

    /**
      * Sets the directory server host name.
      *
      * @param host  the directory server host name
      */
    public void setUserHost(String host) {
        put(KEY_USER_HOST, host);
    }


    /**
      * Returns the directory server host name.
      *
      * @return  the directory server host name
      */
    public String getUserHost() {
        String sReturn = (String) get(KEY_USER_HOST);
        if (sReturn == null) {
            sReturn = getHost();
        }
        return sReturn;
    }


    /**
      * Sets the directory server port number.
      *
      * @param port  the directory server port number
      */
    public void setPort(int port) {
        put(KEY_PORT, Integer.valueOf(port));
    }


    /**
      * Returns the directory server port number.
      *
      * @return  the directory server port number
      */
    public int getPort() {
        return ((Integer) get(KEY_PORT)).intValue();
    }

    /**
      * Sets the directory server port number.
      *
      * @param port  the directory server port number
      */
    public void setUserPort(int port) {
        put(KEY_USER_PORT, Integer.valueOf(port));
    }


    /**
      * Returns the directory server port number.
      *
      * @return  the directory server port number
      */
    public int getUserPort() {
        Integer iPort = (Integer) get(KEY_USER_PORT);
        if (iPort != null) {
            return ((Integer) get(KEY_USER_PORT)).intValue();
        } else {
            return getPort();
        }
    }


    /**
      * Sets the user ID.
      *
      * @param authDN  the user ID
      */
    public void setAuthenticationDN(String uid) {
        put(KEY_AUTHENTICATION_DN, uid);
    }

    /**
      * Returns the user ID.
      *
      * @return  the user ID
      */
    public String getAuthenticationDN() {
        return (String) get(KEY_AUTHENTICATION_DN);
    }


    /**
      * Sets the user password.
      *
      * @param password  the user password
      */
    public void setAuthenticationPassword(String password) {
        put(KEY_AUTHENTICATION_PASSWORD, password);
    }


    /**
      * Returns the user password.
      *
      * @return  the user password
      */
    public String getAuthenticationPassword() {
        return (String) get(KEY_AUTHENTICATION_PASSWORD);
    }


    /**
      * Sets the base DN for the current directory server.
      *
      * @param baseDN  the base DN
      */
    public void setBaseDN(String baseDN) {
        put(KEY_BASE_DN, baseDN);
    }


    /**
      * Returns the base DN for the current directory server.
      *
      * @return  the base DN
      */
    public String getBaseDN() {
        return (String) get(KEY_BASE_DN);
    }

    /**
      * Sets the base DN for the current directory server.
      *
      * @param baseDN  the base DN
      */
    public void setUserBaseDN(String baseDN) {
        put(KEY_USER_BASE_DN, baseDN);
    }


    /**
      * Returns the base DN for the current directory server.
      *
      * @return  the base DN
      */
    public String getUserBaseDN() {
        String sReturn = (String) get(KEY_USER_BASE_DN);
        if (sReturn == null) {
            sReturn = getBaseDN();
        }
        return sReturn;
    }

    /**
      * Sets the connection to the directory server.
      *
      * @param ldc  the connection to the directory server
      */
    public void setLDAPConnection(LDAPConnection ldc) {
        put(KEY_LDAP_CONNECTION, ldc);
    }


    /**
      * Returns the connection to the directory server.
      *
      * @return  the connection to the directory server
      */
    public LDAPConnection getLDAPConnection() {
        LDAPConnection ldc = (LDAPConnection) get(KEY_LDAP_CONNECTION);
        return ldc;
    }

    /**
      * Sets the connection to the directory server.
      *
      * @param ldc  the connection to the directory server
      */
    public void setUserLDAPConnection(LDAPConnection ldc) {
        put(KEY_USER_LDAP_CONNECTION, ldc);
    }


    /**
      * Returns the connection to the directory server.
      *
      * @return  the connection to the directory server
      */
    public LDAPConnection getUserLDAPConnection() {
        LDAPConnection ldc = (LDAPConnection) get(KEY_USER_LDAP_CONNECTION);
        if (ldc == null) {
            ldc = getLDAPConnection();
        }
        return ldc;
    }


    /**
      * Sets the current DN.
      *
      * @param dn  the current DN
      */
    public void setCurrentDN(String dn) {
        put(KEY_CURRENT_DN, dn);
    }


    /**
      * Returns the current DN.
      *
      * @return  the current DN
      */
    public String getCurrentDN() {
        return (String) get(KEY_CURRENT_DN);
    }


    /**
      * Sets the admin URL.
      *
      * @param url  the admin URL
      */
    public void setAdminURL(String url) {
        put(KEY_ADMIN_URL, url);
    }


    /**
      * Returns the admin URL.
      *
      * @return  the admin URL
      */
    public String getAdminURL() {
        return (String) get(KEY_ADMIN_URL);
    }


    /**
      * Sets the OS for the host where admin is running.
      *
      * @param os  the admin OS
      */
    public void setAdminOS(String os) {
        put(KEY_ADMIN_OS, os);
    }


    /**
      * Returns the OS for the host where admin is running.
      *
      * @return  the admin OS
      */
    public String getAdminOS() {
        return (String) get(KEY_ADMIN_OS);
    }


    /**
      * Sets the ACL DN.
      *
      * @param dn  the ACL DN
      */
    public void setAclDN(String dn) {
        put(KEY_ACL_DN, dn);
    }


    /**
      * Returns the ACL DN.
      *
      * @return  the ACL DN
      */
    public String getAclDN() {
        return (String) get(KEY_ACL_DN);
    }


    /**
      * Sets the user and group DN.
      *
      * @param dn  the user and group DN
      */
    public void setUserGroupDN(String dn) {
        put(KEY_USER_GROUP_DN, dn);
    }


    /**
      * Returns the user and group DN.
      *
      * @return  the user and group DN
      */
    public String getUserGroupDN() {
        return (String) get(KEY_USER_GROUP_DN);
    }


    /**
      * Sets the user preference DN.
      *
      * @param dn  the user preference DN
      */
    public void setUserPreferenceDN(String dn) {
        put(KEY_USER_PREFERENCE_DN, dn);
    }


    /**
      * Returns the user preference DN.
      *
      * @return  the user preference DN
      */
    public String getUserPreferenceDN() {
        return (String) get(KEY_USER_PREFERENCE_DN);
    }

    /**
      * Sets the applet.
      *
      * @param applet  the applet
      */
    public void setApplet(Applet applet) {
        put(KEY_APPLET, applet);
    }


    /**
      * Returns the applet.
      *
      * @return  the applet
      */
    public Applet getApplet() {
        return (Applet) get(KEY_APPLET);
    }

    /**
      * Sets the authentication values hashtable.
      *
      * @param ht the values hashtable.
      */
    public void setAuthenticationValues(Hashtable ht) {
        put(KEY_AUTH_VALUES, ht);
    }

    /**
      * Returns the authentication values hashtable.
      *
      * @return the values hashtable.
      */
    public Hashtable getAuthenticationValues() {
        return (Hashtable) get(KEY_AUTH_VALUES);
    }

    /**
      * Returns the frame.
      *
      * @return  the frame
      */
    public JFrame getFrame() {
        if (frame == null) {
            frame = new JFrame();
        }
        return frame;
    }


    /**
      * Returns a new ConsoleInfo object which is a deep copy of this
      * ConsoleInfo object.
      *
      * @return  new ConsoleInfo object
      */
    public synchronized Object clone() {
        Debug.println(9, "TRACE ConsoleInfo.clone: tracking cloning of ConsoleInfo for performance tuning");
        ConsoleInfo newObject = (ConsoleInfo) super.clone();
        Enumeration eKey = keys();
        while (eKey.hasMoreElements()) {
            Object oKey = eKey.nextElement();
            Object oValue = get(oKey);
            newObject.put(oKey, oValue);
        }
        return newObject;
    }


    /**
      * Returns the primary contents of this ConsoleInfo object as a String.
      *
      * @return  the primary contents of this object as a String
      */
    public String toString() {
        return "ConsoleInfo(" + getHost() + ", " + getPort() + ", " +
                getAuthenticationDN() + ", " +
                getAuthenticationPassword() + ", " + getBaseDN() + ")";
    }
}
