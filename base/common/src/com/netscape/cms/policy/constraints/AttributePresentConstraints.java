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
package com.netscape.cms.policy.constraints;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * This checks if attribute present.
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
public class AttributePresentConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_ENABLED = "enabled";
    protected static final String PROP_LDAP = "ldap";

    protected String mName = null;
    protected String mImplName = null;

    private ILogger mLogger = CMS.getLogger();

    private IConfigStore mConfig = null;
    private IConfigStore mLdapConfig = null;
    private ILdapConnFactory mConnFactory = null;
    private LDAPConnection mCheckAttrLdapConnection = null;

    public AttributePresentConstraints() {
        DESC = "Rejects request if ldap attribute is not present in the " +
                "directory.";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String params[] = {
                PROP_ATTR + ";string,required;Ldap attribute to check presence of (default " +
                        DEF_ATTR + ")",
                PROP_VALUE + ";string;if this parameter is non-empty, the attribute must " +
                        "match this value for the request to proceed ",
                PROP_LDAP_BASE + ";string,required;Base DN to start searching " +
                        "under. If your user's DN is 'uid=jsmith, o=company', you " +
                        "might want to use 'o=company' here",
                PROP_LDAP_HOST + ";string,required;" +
                        "LDAP host to connect to",
                PROP_LDAP_PORT + ";number,required;" +
                        "LDAP port number (use 389, or 636 if SSL)",
                PROP_LDAP_SSL + ";boolean;" +
                        "Use SSL to connect to directory?",
                PROP_LDAP_VER + ";choice(3,2),required;" +
                        "LDAP protocol version",
                PROP_LDAP_BIND + ";string;DN to bind as for attribute checking. " +
                        "For example 'CN=Pincheck User'",
                PROP_LDAP_PW + ";password;Enter password used to bind as " +
                        "the above user",
                PROP_LDAP_AUTH + ";choice(BasicAuth,SslClientAuth),required;" +
                        "How to bind to the directory",
                PROP_LDAP_CERT + ";string;If you want to use " +
                        "SSL client auth to the directory, set the client " +
                        "cert nickname here",
                PROP_LDAP_BASE + ";string,required;Base DN to start searching " +
                        "under. If your user's DN is 'uid=jsmith, o=company', you " +
                        "might want to use 'o=company' here",
                PROP_LDAP_MINC + ";number;number of connections " +
                        "to keep open to directory server. Default " + DEF_LDAP_MINC,
                PROP_LDAP_MAXC + ";number;when needed, connection " +
                        "pool can grow to this many (multiplexed) connections. Default " + DEF_LDAP_MAXC,
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-pinpresent",
                IExtendedPluginInfo.HELP_TEXT +
                        ";" + DESC + " This plugin can be used to " +
                        "check the presence (and, optionally, the value) of any LDAP " +
                        "attribute for the user. "
            };

        return params;
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

    // Parameters

    protected static final String PROP_LDAP_HOST = "ldap.ldapconn.host";
    protected static final String DEF_LDAP_HOST = "localhost";

    protected static final String PROP_LDAP_PORT = "ldap.ldapconn.port";
    protected static final Integer DEF_LDAP_PORT = Integer.valueOf(389);

    protected static final String PROP_LDAP_SSL = "ldap.ldapconn.secureConn";
    protected static final Boolean DEF_LDAP_SSL = Boolean.FALSE;

    protected static final String PROP_LDAP_VER = "ldap.ldapconn.version";
    protected static final Integer DEF_LDAP_VER = Integer.valueOf(3);

    protected static final String PROP_LDAP_BIND = "ldap.ldapauth.bindDN";
    protected static final String DEF_LDAP_BIND = "CN=Directory Manager";

    protected static final String PROP_LDAP_PW = "ldap.ldapauth.bindPWPrompt";
    protected static final String DEF_LDAP_PW = "";

    protected static final String PROP_LDAP_CERT = "ldap.ldapauth.clientCertNickname";
    protected static final String DEF_LDAP_CERT = "";

    protected static final String PROP_LDAP_AUTH = "ldap.ldapauth.authtype";
    protected static final String DEF_LDAP_AUTH = "BasicAuth";

    protected static final String PROP_LDAP_BASE = "ldap.ldapconn.basedn";
    protected static final String DEF_LDAP_BASE = "";

    protected static final String PROP_LDAP_MINC = "ldap.ldapconn.minConns";
    protected static final Integer DEF_LDAP_MINC = Integer.valueOf(1);

    protected static final String PROP_LDAP_MAXC = "ldap.ldapconn.maxConns";
    protected static final Integer DEF_LDAP_MAXC = Integer.valueOf(5);

    protected static final String PROP_ATTR = "attribute";
    protected static final String DEF_ATTR = "pin";

    protected static final String PROP_VALUE = "value";
    protected static final String DEF_VALUE = "";

    protected static Vector<String> mParamNames;
    protected static Hashtable<String, Object> mParamDefault;
    protected Hashtable<String, Object> mParamValue = null;

    static {
        mParamNames = new Vector<String>();
        mParamDefault = new Hashtable<String, Object>();
        addParam(PROP_LDAP_HOST, DEF_LDAP_HOST);
        addParam(PROP_LDAP_PORT, DEF_LDAP_PORT);
        addParam(PROP_LDAP_SSL, DEF_LDAP_SSL);
        addParam(PROP_LDAP_VER, DEF_LDAP_VER);
        addParam(PROP_LDAP_BIND, DEF_LDAP_BIND);
        addParam(PROP_LDAP_PW, DEF_LDAP_PW);
        addParam(PROP_LDAP_CERT, DEF_LDAP_CERT);
        addParam(PROP_LDAP_AUTH, DEF_LDAP_AUTH);
        addParam(PROP_LDAP_BASE, DEF_LDAP_BASE);
        addParam(PROP_LDAP_MINC, DEF_LDAP_MINC);
        addParam(PROP_LDAP_MAXC, DEF_LDAP_MAXC);
        addParam(PROP_ATTR, DEF_ATTR);
        addParam(PROP_VALUE, DEF_VALUE);
    };

    protected static void addParam(String name, Object value) {
        mParamNames.addElement(name);
        mParamDefault.put(name, value);
    }

    protected void getStringConfigParam(IConfigStore config, String paramName) {
        try {
            mParamValue.put(
                    paramName, config.getString(paramName, (String) mParamDefault.get(paramName))
                    );
        } catch (Exception e) {
        }
    }

    protected void getIntConfigParam(IConfigStore config, String paramName) {
        try {
            mParamValue.put(
                    paramName, Integer.valueOf(
                            config.getInteger(paramName,
                                    ((Integer) mParamDefault.get(paramName)).intValue()
                                    )
                            )
                    );
        } catch (Exception e) {
        }
    }

    protected void getBooleanConfigParam(IConfigStore config, String paramName) {
        try {
            mParamValue.put(
                    paramName, Boolean.valueOf(
                            config.getBoolean(paramName,
                                    ((Boolean) mParamDefault.get(paramName)).booleanValue()
                                    )
                            )
                    );
        } catch (Exception e) {
        }
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        mParamValue = new Hashtable<String, Object>();

        getStringConfigParam(mConfig, PROP_LDAP_HOST);
        getIntConfigParam(mConfig, PROP_LDAP_PORT);
        getBooleanConfigParam(mConfig, PROP_LDAP_SSL);
        getIntConfigParam(mConfig, PROP_LDAP_VER);
        getStringConfigParam(mConfig, PROP_LDAP_BIND);
        getStringConfigParam(mConfig, PROP_LDAP_PW);
        getStringConfigParam(mConfig, PROP_LDAP_CERT);
        getStringConfigParam(mConfig, PROP_LDAP_AUTH);
        getStringConfigParam(mConfig, PROP_LDAP_BASE);
        getIntConfigParam(mConfig, PROP_LDAP_MINC);
        getIntConfigParam(mConfig, PROP_LDAP_MAXC);
        getStringConfigParam(mConfig, PROP_ATTR);
        getStringConfigParam(mConfig, PROP_VALUE);

        mLdapConfig = mConfig.getSubStore(PROP_LDAP);

        mConnFactory = CMS.getLdapBoundConnFactory();
        mConnFactory.init(mLdapConfig);
        mCheckAttrLdapConnection = mConnFactory.getConn();

    }

    public PolicyResult apply(IRequest r) {
        PolicyResult res = PolicyResult.ACCEPTED;

        String requestType = r.getRequestType();

        if (requestType.equals(IRequest.ENROLLMENT_REQUEST) ||
                requestType.equals(IRequest.RENEWAL_REQUEST)) {

            String uid = r.getExtDataInString(IRequest.HTTP_PARAMS, "uid");

            if (uid == null) {
                log(ILogger.LL_INFO, "did not find UID parameter in request " + r.getRequestId());
                setError(r, CMS.getUserMessage("CMS_POLICY_PIN_UNAUTHORIZED"), "");
                return PolicyResult.REJECTED;
            }

            String userdn = null;

            try {
                String[] attrs = { (String) mParamValue.get(PROP_ATTR) };
                LDAPSearchResults searchResult =
                        mCheckAttrLdapConnection.search((String) mParamValue.get(PROP_LDAP_BASE),
                                LDAPv2.SCOPE_SUB, "(uid=" + uid + ")", attrs, false);

                if (!searchResult.hasMoreElements()) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_NO_PIN_FOUND", uid));
                    setError(r, CMS.getUserMessage("CMS_POLICY_PIN_UNAUTHORIZED"), "");
                    return PolicyResult.REJECTED;
                }

                LDAPEntry entry = (LDAPEntry) searchResult.nextElement();

                userdn = entry.getDN();

                LDAPAttribute attr = entry.getAttribute((String) mParamValue.get(PROP_ATTR));

                /* if attribute not present, reject the request */
                if (attr == null) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_NO_PIN_FOUND", userdn));
                    setError(r, CMS.getUserMessage("CMS_POLICY_PIN_UNAUTHORIZED"), "");
                    return PolicyResult.REJECTED;
                }
                String acceptedValue = ((String) mParamValue.get(PROP_VALUE));

                if (!acceptedValue.equals("")) {
                    int matches = 0;

                    String[] values = attr.getStringValueArray();

                    for (int i = 0; i < values.length; i++) {
                        if (values[i].equals(acceptedValue)) {
                            matches++;
                        }
                    }
                    if (matches == 0) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_NO_PIN_FOUND", userdn));
                        setError(r, CMS.getUserMessage("CMS_POLICY_PIN_UNAUTHORIZED"), "");
                        return PolicyResult.REJECTED;
                    }
                }

                CMS.debug("AttributePresentConstraints: Attribute is present for user: \"" + userdn + "\"");

            } catch (LDAPException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_PIN_UNAUTHORIZED"));
                setError(r, CMS.getUserMessage("CMS_POLICY_PIN_UNAUTHORIZED"), "");
                return PolicyResult.REJECTED;
            }

        }
        return res;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        Enumeration<String> e = mParamNames.elements();

        while (e.hasMoreElements()) {
            try {
                String paramName = e.nextElement();
                String paramValue = mParamValue.get(paramName).toString();
                String temp = paramName + "=" + paramValue;

                params.addElement(temp);
            } catch (Exception ex) {
            }
        }

        return params;
    }

    public Vector<String> getDefaultParams() {
        Vector<String> params = new Vector<String>();

        Enumeration<String> e = mParamNames.elements();

        while (e.hasMoreElements()) {
            try {
                String paramName = e.nextElement();
                String paramValue = mParamDefault.get(paramName).toString();
                String temp = paramName + "=" + paramValue;

                params.addElement(temp);
            } catch (Exception ex) {
            }
        }

        return params;

        /*
         params.addElement("ldap.ldapconn.host=localhost");
         params.addElement("ldap.ldapconn.port=389");
         params.addElement("ldap.ldapconn.secureConn=false");
         params.addElement("ldap.ldapconn.version=3");
         params.addElement("ldap.ldapauth.bindDN=CN=Directory Manager");
         params.addElement("ldap.ldapauth.bindPWPrompt=");
         params.addElement("ldap.ldapauth.clientCertNickname=");
         params.addElement("ldap.ldapauth.authtype=BasicAuth");
         params.addElement("ldap.basedn=");
         params.addElement("ldap.minConns=1");
         params.addElement("ldap.maxConns=5");
         */
    }

    protected void log(int level, String msg) {
        if (mLogger == null)
            return;

        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
                level, "AttributePresentConstraints: " + msg);
    }

}
