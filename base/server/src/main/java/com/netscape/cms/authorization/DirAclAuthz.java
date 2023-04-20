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
package com.netscape.cms.authorization;

import java.util.Collection;
import java.util.Enumeration;

import org.dogtagpki.server.authorization.AuthzManagerConfig;

import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * A class for ldap acls based authorization manager
 * The ldap server used for acls is the cms internal ldap db.
 */
public class DirAclAuthz extends AAclAuthz
        implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DirAclAuthz.class);

    protected static final String PROP_SEARCHBASE = "searchBase";

    private LdapBoundConnFactory mLdapConnFactory;
    private String mBaseDN = null;
    private static boolean needsFlush = false;

    /**
     * If configured, this is an LDAP RDN sequence to be
     * prepended to the LDAP base DN, as the base of the
     * search.  If non-null, the search filter also changes
     * from (cn=aclResources) to (objectclass=CertACLS).
     */
    private String searchBase = null;

    static {
        mExtendedPluginInfo.add("ldap.ldapconn.host;string,required;" +
                "LDAP host to connect to");
        mExtendedPluginInfo.add("ldap.ldapconn.port;number,required;" +
                "LDAP port number (use 389, or 636 if SSL)");
        mExtendedPluginInfo.add("ldap.ldapconn.secureConn;boolean;" +
                "Use SSL to connect to directory?");
        mExtendedPluginInfo.add("ldap.ldapconn.version;choice(3,2);" +
                "LDAP protocol version");
        mExtendedPluginInfo.add("ldap.basedn;string,required;Base DN to start sarching under.");
        mExtendedPluginInfo.add("ldap.minConns;number;number of connections " +
                "to keep open to directory server. Default 5.");
        mExtendedPluginInfo.add("ldap.maxConns;number;when needed, connection "
                +
                "pool can grow to this many (multiplexed) connections. Default 1000");
    }

    /**
     * Default constructor
     */
    public DirAclAuthz() {

        /* Holds configuration parameters accepted by this implementation.
         * This list is passed to the configuration console so configuration
         * for instances of this implementation can be configured through the
         * console.
         */
        mConfigParams =
                new String[] {
                        "ldap.ldapconn.host",
                        "ldap.ldapconn.port",
                        "ldap.ldapconn.secureConn",
                        "ldap.ldapconn.version",
                        "ldap.basedn",
                        "ldap.minConns",
                        "ldap.maxConns",
                };
    }

    @Override
    public void init(String name, String implName, AuthzManagerConfig config) throws EBaseException {

        super.init(name, implName, config);

        EngineConfig cs = engine.getConfig();

        searchBase = config.getString(PROP_SEARCHBASE, null);

        LDAPConfig ldapConfig = config.getLDAPConfig();

        if (ldapConfig == null) {
            logger.warn("DirAclAuthz: failed to get config ldap info");
            return;
        }

        mBaseDN = ldapConfig.getBaseDN();
        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();

        try {
            @SuppressWarnings("unused")
            String hostname = connConfig.getString("host"); // check for errors
        } catch (EBaseException e) {
            logger.warn("DirAclAuthz: " + e.getMessage(), e);
            if (engine.isPreOpMode()) {
                logger.warn("DirAclAuthz: Ignore exception in pre-op mode");
                return;
            }
        }

        PKISocketConfig socketConfig = cs.getSocketConfig();

        mLdapConnFactory = new LdapBoundConnFactory("DirAclAuthz");
        mLdapConnFactory.setCMSEngine(engine);
        mLdapConnFactory.init(socketConfig, ldapConfig, engine.getPasswordStore());

        loadACLs();

        logger.info("DirAclAuthz: initialization done");
    }

    public void loadACLs() throws EBaseException {

        logger.info("DirAclAuthz: Loading ACL resources");

        String baseDN = mBaseDN;
        String filter = "cn=aclResources";

        if (searchBase != null) {
            baseDN = String.join(",", searchBase, baseDN);
            filter = "objectclass=CertACLs";
        }

        logger.debug("DirAclAuthz: Searching " + baseDN + " for " + filter);

        LDAPConnection conn = null;

        try {
            conn = getConn();
            LDAPSearchResults res = conn.search(baseDN, LDAPv3.SCOPE_SUB, filter, null, false);

            if (!res.hasMoreElements()) {
                logger.info("DirAclAuthz: ACL resources not found");
                return;
            }

            LDAPEntry entry = (LDAPEntry) res.nextElement();
            logger.info("DirAclAuthz: ACL resources found: " + entry.getDN());

            LDAPAttribute aclRes = entry.getAttribute("resourceACLS");
            Enumeration<String> en = aclRes.getStringValues();

            while (en.hasMoreElements()) {
                String acl = en.nextElement();
                logger.info("DirAclAuthz: - " + acl);
                addACLs(acl);
            }

        } catch (LDAPException e) {
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_CONNECT_LDAP_FAIL", e.getMessage()), e);

        } finally {
            returnConn(conn);
        }
    }

    /**
     * update acls. when memory update is done, flush to ldap.
     * <p>
     * Currently, it is possible that when the memory is updated successfully, and the ldap isn't, the memory upates
     * lingers. The result is that the changes will only be done on ldap at the next update, or when the system shuts
     * down, another flush will be attempted.
     *
     * @param id is the resource id
     * @param rights The allowable rights for this resource
     * @param strACLs has the same format as a resourceACLs entry acis
     *            on the ldap server
     * @param desc The description for this resource
     */
    @Override
    public void updateACLs(String id, String rights, String strACLs,
            String desc) throws EACLsException {
        try {
            super.updateACLs(id, rights, strACLs, desc);
            flushResourceACLs();
            needsFlush = false;
        } catch (EACLsException ex) {
            // flushing failed, set flag
            needsFlush = true;

            logger.error("DirAclAuthz: " + CMS.getLogMessage("AUTHZ_EVALUATOR_FLUSH_RESOURCES", ex.toString()), ex);

            throw ex;
        }
    }

    /**
     * updates resourceACLs to ldap.
     */
    protected void flushResourceACLs() throws EACLsException {
        // ldap update
        LDAPConnection conn = null;

        try {
            LDAPAttribute attrs = new LDAPAttribute("resourceACLS");
            LDAPModificationSet mod = new LDAPModificationSet();

            Collection<ACL> acls = getACLs();

            if (!acls.isEmpty()) {
                for (ACL a : acls) {
                    for (String s : a.getResourceACLs()) {
                        attrs.addValue(s);
                    }
                }

                mod.add(LDAPModification.REPLACE, attrs);

                conn = getConn();
                conn.modify("cn=aclResources," + mBaseDN, mod);
            }
        } catch (LDAPException ex) {
            System.out.println(ex.toString());
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_UPDATE_FAIL"));
        } catch (Exception ex) {
            System.out.println(ex.toString());
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_UPDATE_FAIL"));
        } finally {
            returnConn(conn);
        }
    }

    protected LDAPConnection getConn() throws ELdapException {
        return mLdapConnFactory.getConn();
    }

    protected void returnConn(LDAPConnection conn) {
        mLdapConnFactory.returnConn(conn);
    }

    /**
     * graceful shutdown
     */
    @Override
    public void shutdown() {
        if (needsFlush) {
            // flush the changes
            try {
                flushResourceACLs();
            } catch (EACLsException e) {
                // flushing failed again...too bad
                logger.warn("DirAclAuthz: " + CMS.getLogMessage("AUTHZ_EVALUATOR_FLUSH_ERROR", e.toString()), e);
            }
        }

        try {
            if (mLdapConnFactory != null) mLdapConnFactory.reset();
        } catch (ELdapException e) {
            logger.warn("DirAclAuthz: " + CMS.getLogMessage("AUTHZ_EVALUATOR_LDAP_ERROR", e.toString()), e);
        }
    }

}
