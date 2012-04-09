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

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;

/**
 * This represnets a listener that removes pin from LDAP directory.
 *
 * @version $Revision$, $Date$
 */
public class PinRemovalListener implements IRequestListener {
    protected static final String PROP_ENABLED = "enabled";
    protected static final String PROP_LDAP = "ldap";
    protected static final String PROP_BASEDN = "ldap.basedn";
    protected static final String PROP_PINATTR = "pinAttr";

    protected String mName = null;
    protected String mImplName = null;
    protected String mBaseDN = null;
    protected String mPinAttr = null;

    private boolean mEnabled = false;
    private ILogger mLogger = CMS.getLogger();

    private IConfigStore mConfig = null;
    private IConfigStore mLdapConfig = null;
    private ILdapConnFactory mConnFactory = null;
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
        mName = name;
        mImplName = ImplName;
        mConfig = config;

        mLdapConfig = mConfig.getSubStore(PROP_LDAP);
        mConnFactory = CMS.getLdapBoundConnFactory();
        mConnFactory.init(mLdapConfig);
        mRemovePinLdapConnection = mConnFactory.getConn();

        mEnabled = mConfig.getBoolean(PROP_ENABLED, false);
        mBaseDN = mConfig.getString(PROP_BASEDN, "");
        mPinAttr = mConfig.getString(PROP_PINATTR, "pin");

    }

    public void accept(IRequest r) {
        if (mEnabled != true)
            return;

        String rs = r.getRequestStatus().toString();

        CMS.debug("PinRemovalListener: Request status: " + rs);
        if (!rs.equals("complete")) {
            CMS.debug("PinRemovalListener: - request not complete - not removing pin");
            return;
        }
        String requestType = r.getRequestType();

        if (requestType.equals(IRequest.ENROLLMENT_REQUEST) ||
                requestType.equals(IRequest.RENEWAL_REQUEST)) {

            String uid = r.getExtDataInString(
                    IRequest.HTTP_PARAMS, "uid");

            if (uid == null) {
                log(ILogger.LL_INFO, "did not find UID parameter in this request");
                return;
            }

            String userdn = null;

            try {
                LDAPSearchResults res = mRemovePinLdapConnection.search(mBaseDN,
                        LDAPv2.SCOPE_SUB, "(uid=" + uid + ")", null, false);

                if (!res.hasMoreElements()) {
                    log(ILogger.LL_SECURITY, "uid " + uid + " does not exist in the ldap " +
                            " server. Could not remove pin");
                    return;
                }

                LDAPEntry entry = (LDAPEntry) res.nextElement();

                userdn = entry.getDN();

                mRemovePinLdapConnection.modify(userdn,
                        new LDAPModification(
                                LDAPModification.DELETE,
                                new LDAPAttribute(mPinAttr)));

                log(ILogger.LL_INFO, "Removed pin for user \"" + userdn + "\"");

            } catch (LDAPException e) {
                log(ILogger.LL_SECURITY, "could not remove pin for " + userdn);
            }

        }
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
                level, "PinRemovalListener: " + msg);
    }

    public void set(String name, String val) {
    }
}
