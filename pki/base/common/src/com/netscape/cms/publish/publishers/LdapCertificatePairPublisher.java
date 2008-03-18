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


import netscape.ldap.*;
import java.security.cert.*;
import java.io.*;
import java.util.*;
import netscape.security.x509.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;


/** 
 * module for publishing a cross certificate pair to ldap
 * crossCertificatePair attribute
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class LdapCertificatePairPublisher 
    implements ILdapPublisher, IExtendedPluginInfo {
    public static final String LDAP_CROSS_CERT_PAIR_ATTR = "crossCertificatePair;binary";
    public static final String LDAP_CA_OBJECTCLASS = "certificationAuthority";

    protected String mCrossCertPairAttr = LDAP_CROSS_CERT_PAIR_ATTR;
    protected String mCaObjectclass = LDAP_CA_OBJECTCLASS;

    private ILogger mLogger = CMS.getLogger();
    private boolean mInited = false;
    protected IConfigStore mConfig = null;

    /**
     * constructor constructs default values.
     */
    public LdapCertificatePairPublisher() {
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String s[] = {
                "crossCertPairAttr;string;Name of Ldap attribute in which to store cross certificates",
                "caObjectClass;string;The name of the objectclass which should be " +
                "added to this entry, if it does not already exist",
                IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-ldappublish-publisher-crosscertpairpublisher",
                IExtendedPluginInfo.HELP_TEXT +
                ";This plugin knows how to publish the CA cert to " +
                "'certificateAuthority'-type entries"
            };

        return s;
    }

    public String getImplName() {
        return "LdapCertificatePairPublisher";
    }

    public String getDescription() {
        return "LdapCertificatePairPublisher";
    }

    public Vector getInstanceParams() {
        Vector v = new Vector();

        v.addElement("crossCertPairAttr=" + mCrossCertPairAttr);
        v.addElement("caObjectClass=" + mCaObjectclass);
        return v;
    }

    public Vector getDefaultParams() {
        Vector v = new Vector();

        v.addElement("crossCertPairAttr=" + mCrossCertPairAttr);
        v.addElement("caObjectClass=" + mCaObjectclass);
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
        mCrossCertPairAttr = mConfig.getString("crossCertPairAttr", LDAP_CROSS_CERT_PAIR_ATTR);
        mCaObjectclass = mConfig.getString("caObjectclass", 
                    LDAP_CA_OBJECTCLASS);
        mInited = true;
    }

    // don't think anyone would ever use this but just in case.
    public LdapCertificatePairPublisher(String crossCertPairAttr, String caObjectclass) {
        mCrossCertPairAttr = crossCertPairAttr;
        mCaObjectclass = caObjectclass;
        mInited = true;
    }

    /**
     * Gets the Certificate Authority object class to convert to.
     */
    public String getCAObjectclass() {
        return mCaObjectclass;
    }

    /**
     * returns the cross cert pair attribute where it'll be published.
     */
    public String getXCertAttrName() {
        return mCrossCertPairAttr;
    }

    /**
     * publish a certificatePair
     *    -should not be called from listeners.
     * @param conn the LDAP connection
     * @param dn dn of the entry to publish the XcertificatePair
     * @param pair the Xcertificate bytes  object.
     */
    public synchronized void publish(LDAPConnection conn, String dn, Object pair)
        throws ELdapException {
        publish(conn, dn, (byte[]) pair);
    }

    /**
     * publish a certificatePair
     *    -should not be called from listeners.
     * @param conn the LDAP connection
     * @param dn dn of the entry to publish the XcertificatePair
     * @param pair the cross cert bytes
     */
    public synchronized void publish(LDAPConnection conn, String dn,
        byte[] pair)
        throws ELdapException {

        if (conn == null) {
            log(ILogger.LL_INFO, "LdapCertificatePairPublisher: no LDAP connection");
            return;
        }

        try {
            // check to see if already published
            LDAPSearchResults res = 
                conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)", 
                    new String[] { "objectclass", "crosscertificatepair;binary" }, false);
            LDAPEntry entry = res.next();
            LDAPAttribute certPairs = entry.getAttribute("crosscertificatepair;binary");

            if (LdapUserCertPublisher.ByteValueExists(certPairs, pair) 
                == true) {
                CMS.debug("LdapCertificatePairPublisher: cross cert pair bytes exist in publishing directory, do not publish again.");
                return;
            }

            // publish certificatePair
            LDAPModificationSet modSet = new LDAPModificationSet();

            modSet.add(LDAPModification.ADD, 
                new LDAPAttribute(mCrossCertPairAttr, pair));
            CMS.debug("LdapCertificatePairPublisher: in publish() about to publish with dn=" + dn);

            conn.modify(dn, modSet); 
            CMS.debug("LdapCertificatePairPublisher: in publish() just published");
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISHER_EXCEPTION", "", e.toString()));
                throw new ELdapException("error publishing cross cert pair:" + e.toString());
            }
        }
        return;
    }

    /**
     * unsupported
     */
    public void unpublish(LDAPConnection conn, String dn, Object certObj)
        throws ELdapException {
        CMS.debug("LdapCertificatePairPublisher: unpublish() is unsupported in this revision");
    }

    /**
     * handy routine for logging in this class.
     */
    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
            "LdapCertificatePairPublisher: " + msg);
    }

}
