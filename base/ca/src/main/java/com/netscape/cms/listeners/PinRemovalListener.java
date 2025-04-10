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
package com.netscape.cms.listeners;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.request.Request;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * This represnets a listener that removes pin from LDAP directory.
 */
public class PinRemovalListener extends RequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PinRemovalListener.class);

    protected static final String PROP_ENABLED = "enabled";
    protected static final String PROP_LDAP = "ldap";
    protected static final String PROP_BASEDN = "ldap.basedn";
    protected static final String PROP_PINATTR = "pinAttr";

    protected String mName = null;
    protected String mImplName = null;
    protected String mBaseDN = null;
    protected String mPinAttr = null;

    private boolean mEnabled = false;

    private ConfigStore mConfig;
    private LDAPConfig mLdapConfig;
    private LdapBoundConnFactory mConnFactory;
    private LDAPConnection mRemovePinLdapConnection = null;

    public PinRemovalListener() {
    }

    public String getName() {
        return mName;
    }

    public String getImplName() {
        return mImplName;
    }

    public ConfigStore getConfigStore() {
        return mConfig;
    }

    public void shutdown() {
    }

    protected String[] configParams = { "a" };

    public String[] getConfigParams()
            throws EBaseException {

        return configParams;
    }

    @Override
    public void init(Subsystem sub, ConfigStore config) throws EBaseException {
        init(null, null, config);
    }

    public void init(String name, String ImplName, ConfigStore config)
            throws EBaseException {

        mName = name;
        mImplName = ImplName;
        mConfig = config;

        mLdapConfig = mConfig.getSubStore(PROP_LDAP, LDAPConfig.class);

        mConnFactory = engine.createLdapBoundConnFactory("PinRemovalListener", mLdapConfig);

        mRemovePinLdapConnection = mConnFactory.getConn();

        mEnabled = mConfig.getBoolean(PROP_ENABLED, false);
        mBaseDN = mConfig.getString(PROP_BASEDN, "");
        mPinAttr = mConfig.getString(PROP_PINATTR, "pin");

    }

    @Override
    public void accept(Request r) {
        if (mEnabled != true)
            return;

        String rs = r.getRequestStatus().toString();

        logger.debug("PinRemovalListener: Request status: " + rs);
        if (!rs.equals("complete")) {
            logger.warn("PinRemovalListener: - request not complete - not removing pin");
            return;
        }
        String requestType = r.getRequestType();

        if (requestType.equals(Request.ENROLLMENT_REQUEST) ||
                requestType.equals(Request.RENEWAL_REQUEST)) {

            String uid = r.getExtDataInString(
                    Request.HTTP_PARAMS, "uid");

            if (uid == null) {
                logger.warn("PinRemovalListener: did not find UID parameter in this request");
                return;
            }

            String userdn = null;

            try {
                LDAPSearchResults res = mRemovePinLdapConnection.search(mBaseDN,
                        LDAPv3.SCOPE_SUB, "(uid=" + uid + ")", null, false);

                if (!res.hasMoreElements()) {
                    logger.warn("PinRemovalListener: uid " + uid + " does not exist in the ldap server. Could not remove pin");
                    return;
                }

                LDAPEntry entry = res.next();

                userdn = entry.getDN();

                mRemovePinLdapConnection.modify(userdn,
                        new LDAPModification(
                                LDAPModification.DELETE,
                                new LDAPAttribute(mPinAttr)));

                logger.info("PinRemovalListener: Removed pin for user \"" + userdn + "\"");

            } catch (LDAPException e) {
                logger.warn("PinRemovalListener: could not remove pin for " + userdn, e);
            }

        }
    }

    @Override
    public void set(String name, String val) {
    }
}
