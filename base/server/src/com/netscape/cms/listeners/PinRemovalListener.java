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
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

/**
 * This represnets a listener that removes pin from LDAP directory.
 *
 * @version $Revision$, $Date$
 */
public class PinRemovalListener implements IRequestListener {

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

    private IConfigStore mConfig = null;
    private IConfigStore mLdapConfig = null;
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

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void shutdown() {
    }

    protected String[] configParams = { "a" };

    public String[] getConfigParams()
            throws EBaseException {

        return configParams;
    }

    public void init(ISubsystem sub, IConfigStore config) throws EBaseException {
        init(null, null, config);
    }

    public void init(String name, String ImplName, IConfigStore config)
            throws EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        mName = name;
        mImplName = ImplName;
        mConfig = config;

        mLdapConfig = mConfig.getSubStore(PROP_LDAP);
        mConnFactory = new LdapBoundConnFactory("PinRemovalListener");
        mConnFactory.init(cs, mLdapConfig, engine.getPasswordStore());

        mRemovePinLdapConnection = mConnFactory.getConn();

        mEnabled = mConfig.getBoolean(PROP_ENABLED, false);
        mBaseDN = mConfig.getString(PROP_BASEDN, "");
        mPinAttr = mConfig.getString(PROP_PINATTR, "pin");

    }

    public void accept(IRequest r) {
        if (mEnabled != true)
            return;

        String rs = r.getRequestStatus().toString();

        logger.debug("PinRemovalListener: Request status: " + rs);
        if (!rs.equals("complete")) {
            logger.warn("PinRemovalListener: - request not complete - not removing pin");
            return;
        }
        String requestType = r.getRequestType();

        if (requestType.equals(IRequest.ENROLLMENT_REQUEST) ||
                requestType.equals(IRequest.RENEWAL_REQUEST)) {

            String uid = r.getExtDataInString(
                    IRequest.HTTP_PARAMS, "uid");

            if (uid == null) {
                logger.warn("PinRemovalListener: did not find UID parameter in this request");
                return;
            }

            String userdn = null;

            try {
                LDAPSearchResults res = mRemovePinLdapConnection.search(mBaseDN,
                        LDAPv2.SCOPE_SUB, "(uid=" + uid + ")", null, false);

                if (!res.hasMoreElements()) {
                    logger.warn("PinRemovalListener: uid " + uid + " does not exist in the ldap server. Could not remove pin");
                    return;
                }

                LDAPEntry entry = (LDAPEntry) res.nextElement();

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

    public void set(String name, String val) {
    }
}
