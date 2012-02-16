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
// (C) 2010 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import netscape.ldap.*;
import com.netscape.cmsutil.password.*;

/**
 * This object stores the values for IP, uid and group based on the cookie id in LDAP.
 * Entries are stored under ou=Security Domain, ou=sessions, $basedn
 */
public class LDAPSecurityDomainSessionTable 
  implements ISecurityDomainSessionTable {

    private long m_timeToLive;

    public LDAPSecurityDomainSessionTable(long timeToLive) {
        m_timeToLive = timeToLive;
    }

    public int addEntry(String sessionId, String ip, 
      String uid, String group) {
        IConfigStore cs = CMS.getConfigStore();
        LDAPConnection conn = null;
        boolean sessions_exists = true;
        int status = FAILURE;

        String basedn = null;
        String sessionsdn = null;
        try {
            basedn = cs.getString("internaldb.basedn");
            sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: addEntry: failed to read basedn" + e);
            return status;
        }

        try {
            // create session entry (if it does not exist)
            conn = getLDAPConn();

            LDAPEntry entry = null;
            LDAPAttributeSet attrs = null;
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "organizationalUnit"));
            attrs.add(new LDAPAttribute("ou", "sessions"));
            entry = new LDAPEntry(sessionsdn, attrs);
            conn.add(entry);
         } catch (Exception e) {
            if ((e instanceof LDAPException) && (((LDAPException) e).getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS)) {
                // continue
            } else {
                CMS.debug("SecurityDomainSessionTable: unable to create ou=sessions:" + e);
                sessions_exists = false;
            }
         }

        // add new entry
        try {
            LDAPEntry entry = null;
            LDAPAttributeSet attrs = null;
            String entrydn = "cn=" + sessionId + "," + sessionsdn;
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "securityDomainSessionEntry"));
            attrs.add(new LDAPAttribute("cn", sessionId));
            attrs.add(new LDAPAttribute("host", ip));
            attrs.add(new LDAPAttribute("uid", uid));
            attrs.add(new LDAPAttribute("cmsUserGroup", group));
            attrs.add(new LDAPAttribute("dateOfCreate", Long.toString((new Date()).getTime())));

            entry = new LDAPEntry(entrydn, attrs);
            if (sessions_exists) {
                conn.add(entry);
                CMS.debug("SecurityDomainSessionTable: added session entry" + sessionId);
                status = SUCCESS;
            }
        } catch(Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to create session entry" + sessionId + ": " + e);
        } 

        try {
            conn.disconnect();
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable:addEntry: Error in disconnecting from database: " + e);
        }
        return status;
    }

    public int removeEntry(String sessionId) {
        IConfigStore cs = CMS.getConfigStore();
        LDAPConnection conn = null;
        int status = FAILURE;
        try {
            String basedn = cs.getString("internaldb.basedn");
            String dn = "cn=" + sessionId + ",ou=sessions,ou=Security Domain," + basedn;
            conn = getLDAPConn();
            conn.delete(dn);
            status = SUCCESS;
        } catch (Exception e) {
            if ((e instanceof LDAPException) && (((LDAPException) e).getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT)) {
                // continue
            } else {
                CMS.debug("SecurityDomainSessionTable: unable to delete session " + sessionId + ": " + e);
            }
        }
        try {
            conn.disconnect();
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: removeEntry: Error in disconnecting from database: " + e);
        }
        return status;
    }

    public boolean isSessionIdExist(String sessionId) {
        IConfigStore cs = CMS.getConfigStore();
        LDAPConnection conn = null;
        boolean ret = false;
        try {
            String basedn = cs.getString("internaldb.basedn");
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(cn=" + sessionId + ")";
            String[] attrs = { "cn" };

            conn = getLDAPConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            if (res.getCount() > 0) ret = true;
        } catch(Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query session " + sessionId + ": " + e);
        }

        try {
            conn.disconnect();
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: isSessionIdExist: Error in disconnecting from database: " + e);
        }
        return ret;
    }


    public Enumeration getSessionIds() {
        IConfigStore cs = CMS.getConfigStore();
        LDAPConnection conn = null;
        Vector ret = new Vector();

        try {
            String basedn = cs.getString("internaldb.basedn");
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(objectclass=securityDomainSessionEntry)";
            String[] attrs = { "cn" };

            conn = getLDAPConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            while (res.hasMoreElements()) {
                LDAPEntry entry = res.next();
                ret.add(entry.getAttribute("cn").getStringValueArray()[0]);
            }
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
                case LDAPException.NO_SUCH_OBJECT:
                    CMS.debug("SecurityDomainSessionTable: getSessionIds():  no sessions have been created");
                    break;
                default:
                    CMS.debug("SecurityDomainSessionTable: unable to query sessionIds due to ldap exception: " + e);
            }
        } catch(Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query sessionIds: " + e);
        }

        try {
            conn.disconnect();
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: getSessionIds: Error in disconnecting from database: " + e);
        }

        return ret.elements();
    }

    private String getStringValue(String sessionId, String attr) {
        IConfigStore cs = CMS.getConfigStore();
        LDAPConnection conn = null;
        String ret = null;
        try { 
            String basedn = cs.getString("internaldb.basedn");
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(cn=" + sessionId + ")";
            String[] attrs = { attr };
            conn = getLDAPConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            if (res.getCount() > 0) { 
                LDAPEntry entry = res.next();
                ret = entry.getAttribute(attr).getStringValueArray()[0];
            }
        } catch(Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query session " + sessionId + ": " + e);
        }

        try {
            conn.disconnect();
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: isSessionIdExist: Error in disconnecting from database: " + e);
        }
        return ret;
    }

    public String getIP(String sessionId) {
        return getStringValue(sessionId, "host");
    }

    public String getUID(String sessionId) {
        return getStringValue(sessionId, "uid");
    }

    public String getGroup(String sessionId) {
        return getStringValue(sessionId, "cmsUserGroup");
    }

    public long getBeginTime(String sessionId) {
        String beginStr = getStringValue(sessionId, "dateOfCreate");
        if (beginStr != null) {
            return Long.parseLong(beginStr);
        }
        return -1;
    }

    public long getTimeToLive() {
        return m_timeToLive;
    }

    public int getSize() {
        IConfigStore cs = CMS.getConfigStore();
        LDAPConnection conn = null;
        int ret =0;

        try {
            String basedn = cs.getString("internaldb.basedn");
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(objectclass=securityDomainSessionEntry)";
            String[] attrs = { "cn" };

            conn = getLDAPConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            ret = res.getCount();
        } catch(Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query sessionIds: " + e);
        }

        try {
            conn.disconnect();
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: getSessionIds: Error in disconnecting from database: " + e);
        }

        return ret;
    }

    private LDAPConnection getLDAPConn()
            throws IOException
    {
        IConfigStore cs = CMS.getConfigStore();

        String host = "";
        String port = "";
        String pwd = null;
        String binddn = "";
        String security = "";
        String clientNick = "";

        IPasswordStore pwdStore = CMS.getPasswordStore();

        if (pwdStore != null) {
            //CMS.debug("SecurityDomainSessionTable: getLDAPConn: password store available");
            pwd = pwdStore.getPassword("internaldb");
        }

        if ( pwd == null) {
           throw new IOException("SecurityDomainSessionTable: Failed to obtain password from password store");
        }

        try {
            host = cs.getString("internaldb.ldapconn.host");
            port = cs.getString("internaldb.ldapconn.port");
            binddn = cs.getString("internaldb.ldapauth.bindDN");
            security = cs.getString("internaldb.ldapconn.secureConn");
            clientNick = cs.getString("internaldb.ldapauth.clientCertNickname");
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: getLDAPConn" + e.toString());
            throw new IOException(
                    "Failed to retrieve LDAP information from CS.cfg.");
        }

        int p = -1;

        try {
            p = Integer.parseInt(port);
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable getLDAPConn: " + e.toString());
            throw new IOException("Port is not valid");
        }

        LDAPConnection conn = null;
        if (!clientNick.equals("")) {
            CMS.debug("SecurityDomainSessionTable getLDAPConn: creating secure (SSL) client auth connection for internal ldap");
            conn = new LDAPConnection(CMS.getLdapJssSSLSocketFactory(clientNick));
        } else if (security.equals("true")) {
            //CMS.debug("SecurityDomainSessionTable getLDAPConn: creating secure (SSL) connection for internal ldap");
            conn = new LDAPConnection(CMS.getLdapJssSSLSocketFactory());
        } else {
          //CMS.debug("SecurityDomainSessionTable getLDAPConn: creating non-secure (non-SSL) connection for internal ldap");
          conn = new LDAPConnection();
        }

        //CMS.debug("SecurityDomainSessionTable connecting to " + host + ":" + p);
        try {
            conn.connect(host, p, binddn, pwd);
        } catch (LDAPException e) {
            CMS.debug("SecurityDomainSessionTable getLDAPConn: " + e.toString());
            throw new IOException("Failed to connect to the internal database.");
        }

        return conn;
    }

}
