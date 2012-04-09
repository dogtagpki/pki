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
package com.netscape.cms.policy.extensions;

import java.util.Locale;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Checks extension presence.
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @deprecated
 * @version $Revision$, $Date$
 */
public class PresenceExt extends APolicyRule {
    private static Vector<String> mDefParams = new Vector<String>();
    @SuppressWarnings("unused")
    private IConfigStore mConfig;
    private String mOID = null;
    private boolean mCritical;
    private int mVersion = 0;
    private String mStreetAddress;
    private String mTelephoneNumber;
    private String mRFC822Name;
    private String mID;
    private String mHostName;
    private int mPortNumber = 0;
    private int mMaxUsers = 0;
    private int mServiceLevel = 0;

    public static final String PROP_IS_CRITICAL = "critical";
    public static final String PROP_OID = "oid";
    public static final String PROP_VERSION = "version";
    public static final String PROP_STREET_ADDRESS = "streetAddress";
    public static final String PROP_TELEPHONE_NUMBER = "telephoneNumber";
    public static final String PROP_RFC822_NAME = "rfc822Name";
    public static final String PROP_ID = "id";
    public static final String PROP_HOSTNAME = "hostName";
    public static final String PROP_PORT_NUMBER = "portNumber";
    public static final String PROP_MAX_USERS = "maxUsers";
    public static final String PROP_SERVICE_LEVEL = "serviceLevel";

    static {
        mDefParams.addElement(PROP_IS_CRITICAL + "=false");
    }

    public PresenceExt() {
        NAME = "PresenceExtPolicy";
        DESC = "Sets Presence Server Extension in certificates.";
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        mCritical = config.getBoolean(PROP_IS_CRITICAL, false);
        mOID = config.getString(PROP_OID, "");
        mVersion = config.getInteger(PROP_VERSION, 0);
        mStreetAddress = config.getString(PROP_STREET_ADDRESS, "");
        mTelephoneNumber = config.getString(PROP_TELEPHONE_NUMBER, "");
        mRFC822Name = config.getString(PROP_RFC822_NAME, "");
        mID = config.getString(PROP_ID, "");
        mHostName = config.getString(PROP_HOSTNAME, "");
        mPortNumber = config.getInteger(PROP_PORT_NUMBER, 0);
        mMaxUsers = config.getInteger(PROP_MAX_USERS, 0);
        mServiceLevel = config.getInteger(PROP_SERVICE_LEVEL, 0);
    }

    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;

        /*
         PresenceServerExtension ext = new PresenceServerExtension(mCritical,
         mOID, mVersion, mStreetAddress,
         mTelephoneNumber, mRFC822Name, mID,
         mHostName, mPortNumber, mMaxUsers, mServiceLevel);
         */

        return res;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        params.addElement(PROP_IS_CRITICAL + "=" + mCritical);
        params.addElement(PROP_OID + "=" + mOID);
        params.addElement(PROP_VERSION + "=" + mVersion);
        params.addElement(PROP_STREET_ADDRESS + "=" + mStreetAddress);
        params.addElement(PROP_TELEPHONE_NUMBER + "=" + mTelephoneNumber);
        params.addElement(PROP_RFC822_NAME + "=" + mRFC822Name);
        params.addElement(PROP_ID + "=" + mID);
        params.addElement(PROP_HOSTNAME + "=" + mHostName);
        params.addElement(PROP_PORT_NUMBER + "=" + mPortNumber);
        params.addElement(PROP_MAX_USERS + "=" + mMaxUsers);
        params.addElement(PROP_SERVICE_LEVEL + "=" + mServiceLevel);
        return params;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_IS_CRITICAL + ";boolean;Criticality",
                PROP_OID + ";string; Object identifier of this extension",
                PROP_VERSION + ";string; version",
                PROP_STREET_ADDRESS + ";string; street address",
                PROP_TELEPHONE_NUMBER + ";string; telephone number",
                PROP_RFC822_NAME + ";string; rfc822 name",
                PROP_ID + ";string; identifier",
                PROP_HOSTNAME + ";string; host name",
                PROP_PORT_NUMBER + ";string; port number",
                PROP_MAX_USERS + ";string; max users",
                PROP_SERVICE_LEVEL + ";string; service level",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-presenceext",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds Presence Server Extension;"

        };

        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return mDefParams;
    }
}
