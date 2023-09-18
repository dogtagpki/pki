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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.SecurityDomainSessionTable;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * This object stores the values for IP, uid and group based on the cookie id in LDAP.
 * Entries are stored under ou=Security Domain, ou=sessions, $basedn
 */
public class LDAPSecurityDomainSessionTable
        extends SecurityDomainSessionTable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LDAPSecurityDomainSessionTable.class);

    protected CMSEngine engine;
    private LdapBoundConnFactory mLdapConnFactory;

    public LDAPSecurityDomainSessionTable(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    public void init() throws ELdapException, EBaseException {

        EngineConfig cs = engine.getConfig();
        LDAPConfig internaldb = cs.getInternalDBConfig();

        mLdapConnFactory = engine.createLdapBoundConnFactory("LDAPSecurityDomainSessionTable", internaldb);
    }

    @Override
    public void addEntry(String sessionId, String ip,
            String uid, String group) throws Exception {

        EngineConfig cs = engine.getConfig();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        LDAPConnection conn = null;

        String basedn = ldapConfig.getBaseDN();
        String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;

        try {
            // create session entry (if it does not exist)
            conn = mLdapConnFactory.getConn();

            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "organizationalUnit"));
            attrs.add(new LDAPAttribute("ou", "sessions"));

            LDAPEntry entry = new LDAPEntry(sessionsdn, attrs);

            try {
                conn.add(entry);

            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                    // continue
                } else {
                    logger.error("SecurityDomainSessionTable: Unable to create ou=sessions: " + e.getMessage(), e);
                    throw new PKIException("Unable to create ou=sessions: " + e.getMessage(), e);
                }
            }

            // add new entry
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

            conn.add(entry);

            logger.info("SecurityDomainSessionTable: added session entry " + sessionId);

        } finally {
            try {
                mLdapConnFactory.returnConn(conn);
            } catch (Exception e) {
                logger.warn("Unable to return LDAP connection: " + e.getMessage(), e);
            }
        }
    }

    @Override
    public void removeEntry(String sessionId) throws Exception {

        EngineConfig cs = engine.getConfig();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        LDAPConnection conn = null;
        try {
            String basedn = ldapConfig.getBaseDN();
            String dn = "cn=" + sessionId + ",ou=sessions,ou=Security Domain," + basedn;
            conn = mLdapConnFactory.getConn();
            conn.delete(dn);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                // continue
            } else {
                logger.error("SecurityDomainSessionTable: unable to delete session " + sessionId + ": " + e.getMessage(), e);
                throw new PKIException("Unable to delete session: " + sessionId + ": " + e.getMessage(), e);
            }

        } finally {
            try {
                mLdapConnFactory.returnConn(conn);
            } catch (Exception e) {
                logger.warn("Unable to return LDAP connection: " + e.getMessage(), e);
            }
        }
    }

    @Override
    public boolean sessionExists(String sessionId) throws Exception {

        EngineConfig cs = engine.getConfig();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        LDAPConnection conn = null;
        boolean ret = false;

        try {
            String basedn = ldapConfig.getBaseDN();
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(cn=" + sessionId + ")";
            String[] attrs = { "cn" };

            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv3.SCOPE_SUB, filter, attrs, false);
            if (res.getCount() > 0)
                ret = true;

        } finally {
            try {
                mLdapConnFactory.returnConn(conn);
            } catch (Exception e) {
                logger.warn("Unable to return LDAP connection: " + e.getMessage(), e);
            }
        }

        return ret;
    }

    @Override
    public Enumeration<String> getSessionIDs() throws Exception {

        logger.debug("LDAPSecurityDomainSessionTable: getSessionIds() ");

        EngineConfig cs = engine.getConfig();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        LDAPConnection conn = null;
        Vector<String> ret = new Vector<>();

        try {
            String basedn = ldapConfig.getBaseDN();
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(objectclass=securityDomainSessionEntry)";
            String[] attrs = { "cn" };

            logger.debug("LDAPSecurityDomainSessionTable: searching " + sessionsdn);

            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv3.SCOPE_SUB, filter, attrs, false);
            while (res.hasMoreElements()) {
                LDAPEntry entry = res.next();
                LDAPAttribute sid = entry.getAttribute("cn");
                if (sid == null) {
                    logger.error("LDAPSecurityDomainSessionTable: Missing session ID: " + entry.getDN());
                    throw new Exception("Missing session ID: " + entry.getDN());
                }
                ret.add(sid.getStringValueArray()[0]);
            }

        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
                logger.debug("SecurityDomainSessionTable: no active sessions, ignore");
                break;
            default:
                logger.error("SecurityDomainSessionTable: RC: " + e.getLDAPResultCode());
                throw e;
            }

        } finally {
            try {
                mLdapConnFactory.returnConn(conn);
            } catch (Exception e) {
                logger.warn("Unable to return LDAP connection: " + e.getMessage(), e);
            }
        }

        return ret.elements();
    }

    private String getStringValue(String sessionId, String attr) throws Exception {

        EngineConfig cs = engine.getConfig();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        LDAPConnection conn = null;
        String ret = null;
        try {
            String basedn = ldapConfig.getBaseDN();
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(cn=" + sessionId + ")";
            String[] attrs = { attr };

            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv3.SCOPE_SUB, filter, attrs, false);
            if (res.getCount() > 0) {
                LDAPEntry entry = res.next();
                LDAPAttribute searchAttribute = entry.getAttribute(attr);
                if (searchAttribute == null) {
                    throw new Exception("No Attribute " + attr + " for this session in LDAPEntry "+entry.getDN());
                }
                ret = searchAttribute.getStringValueArray()[0];
            }

        } finally {
            try {
                mLdapConnFactory.returnConn(conn);
            } catch (Exception e) {
                logger.warn("Unable to return LDAP connection: " + e.getMessage(), e);
            }
        }

        return ret;
    }

    @Override
    public String getIP(String sessionId) throws Exception {
        return getStringValue(sessionId, "host");
    }

    @Override
    public String getUID(String sessionId) throws Exception {
        return getStringValue(sessionId, "uid");
    }

    @Override
    public String getGroup(String sessionId) throws Exception {
        return getStringValue(sessionId, "cmsUserGroup");
    }

    @Override
    public long getBeginTime(String sessionId) throws Exception {
        String beginStr = getStringValue(sessionId, "dateOfCreate");
        if (beginStr != null) {
            return Long.parseLong(beginStr);
        }
        return -1;
    }

    @Override
    public int getSize() throws Exception {

        EngineConfig cs = engine.getConfig();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        LDAPConnection conn = null;
        int ret = 0;

        try {
            String basedn = ldapConfig.getBaseDN();
            String sessionsdn = "ou=sessions,ou=Security Domain," + basedn;
            String filter = "(objectclass=securityDomainSessionEntry)";
            String[] attrs = { "cn" };

            conn = mLdapConnFactory.getConn();
            LDAPSearchResults res = conn.search(sessionsdn, LDAPv3.SCOPE_SUB, filter, attrs, false);
            ret = res.getCount();

        } finally {
            try {
                mLdapConnFactory.returnConn(conn);
            } catch (Exception e) {
                logger.warn("Unable to return LDAP connection: " + e.getMessage(), e);
            }
        }


        return ret;
    }

    @Override
    public void shutdown() {
        try {
            mLdapConnFactory.reset();
        } catch (ELdapException e) {
            logger.warn("Unable to reset connection factory");
        }
    }
}
