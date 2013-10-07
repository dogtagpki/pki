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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ca.ICAService;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapPublisher;

/**
 * Interface for mapping a X509 certificate to a LDAP entry
 *
 * @version $Revision$, $Date$
 */
public class LdapEncryptCertPublisher implements ILdapPublisher, IExtendedPluginInfo {
    public static final String LDAP_USERCERT_ATTR = "userCertificate;binary";
    public static final String PROP_REVOKE_CERT = "revokeCert";

    protected String mCertAttr = LDAP_USERCERT_ATTR;
    private ILogger mLogger = CMS.getLogger();
    private IConfigStore mConfig = null;
    private boolean mInited = false;

    public LdapEncryptCertPublisher() {
    }

    public String getImplName() {
        return "LdapEncryptCertPublisher";
    }

    public String getDescription() {
        return "LdapEncryptCertPublisher";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                "certAttr;string;LDAP attribute in which to store the certificate",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-publisher-usercertpublisher",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This plugin knows how to publish user certificates"
            };

        return params;

    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("certAttr=" + mCertAttr);
        return v;
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("certAttr=" + mCertAttr);
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
        mCertAttr = mConfig.getString("certAttr", LDAP_USERCERT_ATTR);
        mInited = true;
    }

    public LdapEncryptCertPublisher(String certAttr) {
        mCertAttr = certAttr;
    }

    /**
     * publish a user certificate
     * Adds the cert to the multi-valued certificate attribute as a
     * DER encoded binary blob. Does not check if cert already exists.
     *
     * @param conn the LDAP connection
     * @param dn dn of the entry to publish the certificate
     * @param certObj the certificate object.
     */
    public void publish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (conn == null)
            return;

        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        X509Certificate cert = (X509Certificate) certObj;

        log(ILogger.LL_INFO, "Publishing " + cert);
        try {
            byte[] certEnc = cert.getEncoded();

            // check if cert already exists.
            LDAPSearchResults res = conn.search(dn, LDAPv2.SCOPE_BASE,
                    "(objectclass=*)", new String[] { mCertAttr }, false);
            LDAPEntry entry = res.next();
            LDAPAttribute attr = getModificationAttribute(entry.getAttribute(mCertAttr), certEnc);

            if (attr == null) {
                log(ILogger.LL_INFO, "publish: " + dn + " already has cert.");
                return;
            }

            // publish
            LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);

            conn.modify(dn, mod);
        } catch (CertificateEncodingException e) {
            CMS.debug("LdapEncryptCertPublisher: error in publish: " + e.toString());
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_USERCERT_ERROR", e.toString()));
            }
        }
        return;
    }

    /**
     * unpublish a user certificate
     * deletes the certificate from the list of certificates.
     * does not check if certificate is already there.
     */
    public void unpublish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        X509Certificate cert = (X509Certificate) certObj;

        try {
            byte[] certEnc = cert.getEncoded();

            // check if cert already deleted.
            LDAPSearchResults res = conn.search(dn, LDAPv2.SCOPE_BASE,
                    "(objectclass=*)", new String[] { mCertAttr }, false);
            LDAPEntry entry = res.next();

            if (!ByteValueExists(entry.getAttribute(mCertAttr), certEnc)) {
                log(ILogger.LL_INFO, dn + " already has not cert");
                return;
            }

            LDAPModification mod = new LDAPModification(LDAPModification.DELETE,
                    new LDAPAttribute(mCertAttr, certEnc));

            conn.modify(dn, mod);
        } catch (CertificateEncodingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_USERCERT_ERROR", e.toString()));
            }
        }
        return;
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "LdapUserCertPublisher: " + msg);
    }

    public LDAPAttribute getModificationAttribute(
            LDAPAttribute attr, byte[] bval) {

        LDAPAttribute at = new LDAPAttribute(attr.getName(), bval);
        // determine if the given cert is a signing or an encryption
        // certificate
        X509CertImpl thisCert = null;

        try {
            thisCert = new X509CertImpl(bval);
        } catch (Exception e) {
        }
        if (thisCert == null) {
            return at;
        }

        @SuppressWarnings("unchecked")
        Enumeration<byte[]> vals = attr.getByteValues();
        byte[] val = null;

        while (vals.hasMoreElements()) {
            val = vals.nextElement();
            try {
                X509CertImpl cert = new X509CertImpl(val);

                log(ILogger.LL_INFO, "Checking " + cert);
                if (CMS.isEncryptionCert(thisCert) &&
                        CMS.isEncryptionCert(cert)) {
                    // skip
                    log(ILogger.LL_INFO, "SKIP ENCRYPTION " + cert);
                    revokeCert(cert);
                } else if (CMS.isSigningCert(thisCert) &&
                        CMS.isSigningCert(cert)) {
                    // skip
                    log(ILogger.LL_INFO, "SKIP SIGNING " + cert);
                    revokeCert(cert);
                } else {
                    at.addValue(val);
                }
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_CHECK_FAILED", e.toString()));
            }
        }
        return at;
    }

    private RevokedCertImpl formCRLEntry(
            BigInteger serialNo, RevocationReason reason)
            throws EBaseException {
        CRLReasonExtension reasonExt = new CRLReasonExtension(reason);
        CRLExtensions crlentryexts = new CRLExtensions();

        try {
            crlentryexts.set(CRLReasonExtension.NAME, reasonExt);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_SET_CRL_REASON", reason.toString(), e.toString()));

            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
        }
        RevokedCertImpl crlentry =
                new RevokedCertImpl(serialNo, new Date(), crlentryexts);

        return crlentry;
    }

    private void revokeCert(X509CertImpl cert)
            throws EBaseException {
        try {
            if (mConfig.getBoolean(PROP_REVOKE_CERT, true) == false) {
                return;
            }
        } catch (EBaseException e) {
            return;
        }
        BigInteger serialNum = cert.getSerialNumber();
        // need to revoke certificate also
        ICertificateAuthority ca = (ICertificateAuthority)
                CMS.getSubsystem("ca");
        ICAService service = (ICAService) ca.getCAService();
        RevokedCertImpl crlEntry = formCRLEntry(
                serialNum, RevocationReason.KEY_COMPROMISE);

        service.revokeCert(crlEntry);
    }

    /**
     * checks if a byte attribute has a certain value.
     */
    public static boolean ByteValueExists(LDAPAttribute attr, byte[] bval) {
        if (attr == null) {
            return false;
        }
        @SuppressWarnings("unchecked")
        Enumeration<byte[]> vals = attr.getByteValues();
        byte[] val = null;

        while (vals.hasMoreElements()) {
            val = vals.nextElement();
            if (PublisherUtils.byteArraysAreEqual(val, bval)) {
                return true;
            }
        }
        return false;
    }

    /**
     * checks if a attribute has a string value.
     */
    public static boolean StringValueExists(LDAPAttribute attr, String sval) {
        if (attr == null) {
            return false;
        }
        @SuppressWarnings("unchecked")
        Enumeration<String> vals = attr.getStringValues();
        String val = null;

        while (vals.hasMoreElements()) {
            val = vals.nextElement();
            if (val.equalsIgnoreCase(sval)) {
                return true;
            }
        }
        return false;
    }

}
