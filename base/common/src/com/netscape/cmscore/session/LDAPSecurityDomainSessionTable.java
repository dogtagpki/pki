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
package com.netscape.cmscore.session;

import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;

/**
 * This object stores the values for IP, uid and group based on the cookie id in LDAP.
 * Entries are stored under ou=Security Domain, ou=sessions, $basedn
 */
public class LDAPSecurityDomainSessionTable
        implements ISecurityDomainSessionTable {

    private long m_timeToLive;
    private ILdapConnFactory mLdapConnFactory = null;

    public LDAPSecurityDomainSessionTable(long timeToLive) throws ELdapException, EBaseException {
        m_timeToLive = timeToLive;
        IConfigStore cs = CMS.getConfigStore();
        IConfigStore internaldb = cs.getSubStore("internaldb");
        mLdapConnFactory = CMS.getLdapBoundConnFactory();
        mLdapConnFactory.init(internaldb);
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
            conn = mLdapConnFactory.getConn();

            LDAPEntry entry = null;
            LDAPAttributeSet attrs = null;
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "organizationalUnit"));
            attrs.add(new LDAPAttribute("ou", "sessions"));
            entry = new LDAPEntry(sessionsdn, attrs);
            conn.add(entry);
        } catch (Exception e) {
            if ((e instanceof LDAPException)
                    && (((LDAPException) e).getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS)) {
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
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to create session entry" + sessionId + ": " + e);
        }

        try {
            mLdapConnFactory.returnConn(conn);
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
            conn = mLdapConnFactory.getConn();
            conn.delete(dn);
            status = SUCCESS;
        } catch (Exception e) {
            if ((e instanceof LDAPException)
                    && (((LDAPException) e).getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT)) {
                // continue
            } else {
                CMS.debug("SecurityDomainSessionTable: unable to delete session " + sessionId + ": " + e);
            }
        }
        try {
            mLdapConnFactory.returnConn(conn);
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

            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            if (res.getCount() > 0)
                ret = true;
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query session " + sessionId + ": " + e);
        }

        try {
            mLdapConnFactory.returnConn(conn);
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: isSessionIdExist: Error in disconnecting from database: " + e);
        }
        return ret;
    }

    public Enumeration<String> getSessionIds() {
        IConfigStore cs = CMS.getConfigStore();
        LDAPConnection conn = null;
        Vector<String> ret = new Vector<String>();

        try {
            String basedn = cs.getString("internaldb.basedn");
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(objectclass=securityDomainSessionEntry)";
            String[] attrs = { "cn" };

            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            while (res.hasMoreElements()) {
                LDAPEntry entry = res.next();
                LDAPAttribute sid = entry.getAttribute("cn");
                if (sid == null) {
                    throw new Exception("Invalid LDAP Entry." + entry.getDN() + " No session id(cn).");
                }
                ret.add(sid.getStringValueArray()[0]);
            }
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
                CMS.debug("SecurityDomainSessionTable: getSessionIds():  no sessions have been created");
                break;
            default:
                CMS.debug("SecurityDomainSessionTable: unable to query sessionIds due to ldap exception: " + e);
            }
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query sessionIds: " + e);
        }

        try {
            mLdapConnFactory.returnConn(conn);
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
            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            if (res.getCount() > 0) {
                LDAPEntry entry = res.next();
                LDAPAttribute searchAttribute = entry.getAttribute(attr);
                if (searchAttribute == null) {
                    throw new Exception("No Attribute " + attr + " for this session in LDAPEntry "+entry.getDN());
                }
                ret = searchAttribute.getStringValueArray()[0];
            }
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query session " + sessionId + ": " + e.getMessage());
        }

        try {
            mLdapConnFactory.returnConn(conn);
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
        int ret = 0;

        try {
            String basedn = cs.getString("internaldb.basedn");
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(objectclass=securityDomainSessionEntry)";
            String[] attrs = { "cn" };

            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv2.SCOPE_SUB, filter, attrs, false);
            ret = res.getCount();
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: unable to query sessionIds: " + e);
        }

        try {
            mLdapConnFactory.returnConn(conn);
        } catch (Exception e) {
            CMS.debug("SecurityDomainSessionTable: getSessionIds: Error in disconnecting from database: " + e);
        }

        return ret;
    }
}
