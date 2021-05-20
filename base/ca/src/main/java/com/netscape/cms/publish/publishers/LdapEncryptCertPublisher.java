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

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICAService;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.publish.ILdapPublisher;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.cert.CertUtils;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

/**
 * Interface for mapping a X509 certificate to a LDAP entry
 *
 * @version $Revision$, $Date$
 */
public class LdapEncryptCertPublisher implements ILdapPublisher, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapEncryptCertPublisher.class);

    public static final String LDAP_USERCERT_ATTR = "userCertificate;binary";
    public static final String PROP_REVOKE_CERT = "revokeCert";

    protected String mCertAttr = LDAP_USERCERT_ATTR;
    private IConfigStore mConfig = null;
    private boolean mInited = false;

    public LdapEncryptCertPublisher() {
    }

    @Override
    public String getImplName() {
        return "LdapEncryptCertPublisher";
    }

    @Override
    public String getDescription() {
        return "LdapEncryptCertPublisher";
    }

    @Override
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

    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<>();

        v.addElement("certAttr=" + mCertAttr);
        return v;
    }

    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<>();

        v.addElement("certAttr=" + mCertAttr);
        return v;
    }

    @Override
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
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
    @Override
    public void publish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (conn == null)
            return;

        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        X509Certificate cert = (X509Certificate) certObj;

        logger.info("Publishing " + cert);
        try {
            byte[] certEnc = cert.getEncoded();

            // check if cert already exists.
            LDAPSearchResults res = conn.search(dn, LDAPv2.SCOPE_BASE,
                    "(objectclass=*)", new String[] { mCertAttr }, false);
            LDAPEntry entry = res.next();
            LDAPAttribute attr = getModificationAttribute(entry.getAttribute(mCertAttr), certEnc);

            if (attr == null) {
                logger.info("publish: " + dn + " already has cert.");
                return;
            }

            // publish
            LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);

            conn.modify(dn, mod);
        } catch (CertificateEncodingException e) {
            logger.error("LdapEncryptCertPublisher: error in publish: " + e.getMessage(), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()), e);
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_USERCERT_ERROR", e.toString()), e);
            }
        }
        return;
    }

    /**
     * unpublish a user certificate
     * deletes the certificate from the list of certificates.
     * does not check if certificate is already there.
     */
    @Override
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
                logger.info(dn + " already has not cert");
                return;
            }

            LDAPModification mod = new LDAPModification(LDAPModification.DELETE,
                    new LDAPAttribute(mCertAttr, certEnc));

            conn.modify(dn, mod);
        } catch (CertificateEncodingException e) {
            logger.error(CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()), e);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()), e);
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_USERCERT_ERROR", e.toString()), e);
            }
        }
        return;
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

        Enumeration<byte[]> vals = attr.getByteValues();
        byte[] val = null;

        while (vals.hasMoreElements()) {
            val = vals.nextElement();
            try {
                X509CertImpl cert = new X509CertImpl(val);

                logger.info("Checking " + cert);
                if (CertUtils.isEncryptionCert(thisCert) &&
                        CertUtils.isEncryptionCert(cert)) {
                    // skip
                    logger.info("SKIP ENCRYPTION " + cert);
                    revokeCert(cert);
                } else if (CertUtils.isSigningCert(thisCert) &&
                        CertUtils.isSigningCert(cert)) {
                    // skip
                    logger.info("SKIP SIGNING " + cert);
                    revokeCert(cert);
                } else {
                    at.addValue(val);
                }
            } catch (Exception e) {
                logger.warn(CMS.getLogMessage("PUBLISH_CHECK_FAILED", e.toString()), e);
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
            logger.error(CMS.getLogMessage("PUBLISH_SET_CRL_REASON", reason.toString(), e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()), e);
        }
        RevokedCertImpl crlentry =
                new RevokedCertImpl(serialNo, new Date(), crlentryexts);

        return crlentry;
    }

    private void revokeCert(X509CertImpl cert)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();

        try {
            if (mConfig.getBoolean(PROP_REVOKE_CERT, true) == false) {
                return;
            }
        } catch (EBaseException e) {
            return;
        }
        BigInteger serialNum = cert.getSerialNumber();
        // need to revoke certificate also
        CertificateAuthority ca = engine.getCA();
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
