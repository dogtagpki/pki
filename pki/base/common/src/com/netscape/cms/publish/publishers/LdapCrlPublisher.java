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
package com.netscape.cms.publish.publishers;


import java.io.*;
import java.util.*;
import java.security.cert.*;
import netscape.ldap.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;

import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;


/**
 * For publishing master or global CRL. 
 * Publishes (replaces) the CRL in the CA's LDAP entry.
 * 
 * @version $Revision$, $Date$
 */
public class LdapCrlPublisher implements ILdapPublisher, IExtendedPluginInfo {
    private ILogger mLogger = CMS.getLogger();
    protected IConfigStore mConfig = null;
    boolean mInited = false;

    public static final String 
        LDAP_CRL_ATTR = "certificateRevocationList;binary";

    String mCrlAttr = LDAP_CRL_ATTR;

    /**
     * constructs ldap crl publisher with default values
     */
    public LdapCrlPublisher() {
    }

    public String getImplName() {
        return "LdapCrlPublisher";
    }

    public String getDescription() {
        return "LdapCrlPublisher";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                "crlAttr;string;Name of Ldap attribute in which to store the CRL",
                IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-ldappublish-publisher-crlpublisher",
                IExtendedPluginInfo.HELP_TEXT +
                ";This plugin knows how to publish CRL's to an LDAP directory"
            };

        return params;
    }

    public Vector getInstanceParams() {
        Vector v = new Vector();

        v.addElement("crlAttr=" + mCrlAttr);
        return v;
    }

    public Vector getDefaultParams() {
        Vector v = new Vector();

        v.addElement("crlAttr=" + mCrlAttr);
        return v;
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void init(IConfigStore config) 
        throws EBaseException {
        if (mInited)
            return;
        mConfig = config;
        mCrlAttr = mConfig.getString("crlAttr", LDAP_CRL_ATTR);
        mInited = true;
    }

    public LdapCrlPublisher(String crlAttr) {
        mCrlAttr = crlAttr;
    }

    /**
     * Replaces the CRL in the certificateRevocationList attribute.
     * CRL's are published as a DER encoded blob.
     */
    public void publish(LDAPConnection conn, String dn, Object crlObj)
        throws ELdapException {
        if (conn == null) {
            log(ILogger.LL_INFO, "publish CRL: no LDAP connection");
            return;
        }

        // Bugscape #56124 - support multiple publishing directory
        // see if we should create local connection
        LDAPConnection altConn = null;
        try {
          String host = mConfig.getString("host", null);
          String port = mConfig.getString("port", null);
          if (host != null && port != null) {
            int portVal = Integer.parseInt(port);
            int version = Integer.parseInt(mConfig.getString("version", "2"));
            String cert_nick = mConfig.getString("clientCertNickname", null);
            LDAPSSLSocketFactoryExt sslSocket = null;
            if (cert_nick != null) {
                sslSocket = CMS.getLdapJssSSLSocketFactory(cert_nick);
            }
            String mgr_dn = mConfig.getString("bindDN", null);
            String mgr_pwd = mConfig.getString("bindPWD", null);

            altConn = CMS.getBoundConnection(host, portVal,
               version,
               sslSocket, mgr_dn, mgr_pwd);
            conn = altConn;
          }
        } catch (LDAPException e) {
          CMS.debug("Failed to create alt connection " + e);
        } catch (EBaseException e) {
          CMS.debug("Failed to create alt connection " + e);
        }

        try {
            byte[] crlEnc = ((X509CRL) crlObj).getEncoded();

            log(ILogger.LL_INFO, "publish CRL: " + dn);
            conn.modify(dn, new LDAPModification(LDAPModification.REPLACE,
                    new LDAPAttribute(mCrlAttr, crlEnc)));
        } catch (CRLException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CRL_ERROR", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CRL_ERROR", e.toString()));
            }
        } finally {
          if (altConn != null) {
             try {
                altConn.disconnect();
             } catch (LDAPException e) {
                // safely ignored
             }
          }
        }

    }

    /**
     * There shouldn't be a need to call this. 
     * CRLs are always replaced but this is implemented anyway in case 
     * there is ever a reason to remove a global CRL.
     */
    public void unpublish(LDAPConnection conn, String dn, Object crlObj)
        throws ELdapException {
        try {
            byte[] crlEnc = ((X509CRL) crlObj).getEncoded();

            LDAPSearchResults res = conn.search(dn, LDAPv2.SCOPE_BASE,
                    "(objectclass=*)", new String[] { mCrlAttr }, false);
            LDAPEntry e = res.next();
            LDAPAttribute crls = e.getAttribute(mCrlAttr);

            if (!LdapUserCertPublisher.ByteValueExists(crls, crlEnc)) {
                log(ILogger.LL_INFO, 
                    "unpublish: " + dn + " already has not CRL");
                return;
            }
            conn.modify(dn, new LDAPModification(LDAPModification.DELETE,
                    new LDAPAttribute(mCrlAttr, crlEnc)));
        } catch (CRLException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CRL_ERROR", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_CRL_ERROR", e.toString()));
            }
        }
        return;
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
            "LdapCrlPublisher: " + msg);
    }
}
