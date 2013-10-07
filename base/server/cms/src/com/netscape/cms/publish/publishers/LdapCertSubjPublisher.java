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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapPublisher;

/**
 * Interface for mapping a X509 certificate to a LDAP entry
 * Publishes a certificate as binary and its subject name.
 * there is one subject name value for each certificate.
 *
 * @version $Revision$, $Date$
 */
public class LdapCertSubjPublisher implements ILdapPublisher {
    public static final String LDAP_CERTSUBJNAME_ATTR = "certSubjectName";
    protected String mCertAttr = LdapUserCertPublisher.LDAP_USERCERT_ATTR;
    protected String mSubjNameAttr = LDAP_CERTSUBJNAME_ATTR;

    private ILogger mLogger = CMS.getLogger();
    private boolean mInited = false;
    protected IConfigStore mConfig = null;

    /**
     * constructor using default certificate subject name and attribute for
     * publishing subject name.
     */
    public LdapCertSubjPublisher() {
    }

    public String getImplName() {
        return "LdapCertSubjPublisher";
    }

    public String getDescription() {
        return "LdapCertSubjPublisher";
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("certAttr=" + mCertAttr);
        v.addElement("subjectNameAttr=" + mSubjNameAttr);
        return v;
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("certAttr=" + mCertAttr);
        v.addElement("subjectNameAttr=" + mSubjNameAttr);
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
        mCertAttr = mConfig.getString("certAttr",
                    LdapUserCertPublisher.LDAP_USERCERT_ATTR);
        mSubjNameAttr = mConfig.getString("certSubjectName",
                    LDAP_CERTSUBJNAME_ATTR);
        mInited = true;
    }

    /**
     * constrcutor using specified certificate attribute and
     * certificate subject name attribute.
     */
    public LdapCertSubjPublisher(String certAttr, String subjNameAttr) {
        mCertAttr = certAttr;
        mSubjNameAttr = subjNameAttr;
    }

    public String getCertAttr() {
        return mCertAttr;
    }

    public String getSubjNameAttr() {
        return mSubjNameAttr;
    }

    public void setSubjNameAttr(String subjNameAttr) {
        mSubjNameAttr = subjNameAttr;
    }

    public void setCertAttr(String certAttr) {
        mCertAttr = certAttr;
    }

    /**
     * publish a user certificate
     * Adds the cert to the multi-valued certificate attribute as a
     * DER encoded binary blob. Does not check if cert already exists.
     * Then adds the subject name of the cert to the subject name attribute.
     *
     * @param conn the LDAP connection
     * @param dn dn of the entry to publish the certificate
     * @param certObj the certificate object.
     * @exception ELdapException if cert or subject name already exists,
     *                if cert encoding fails, if getting cert subject name fails.
     *                Use ELdapException.getException() to find underlying exception.
     */
    public void publish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (conn == null) {
            log(ILogger.LL_INFO, "LdapCertSubjPublisher: no LDAP connection");
            return;
        }

        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        X509Certificate cert = (X509Certificate) certObj;

        try {
            boolean hasCert = false, hasSubjname = false;
            byte[] certEnc = cert.getEncoded();
            String subjName = ((X500Name) cert.getSubjectDN()).toLdapDNString();

            LDAPSearchResults res =
                    conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)",
                            new String[] { mCertAttr, mSubjNameAttr }, false);

            LDAPEntry entry = res.next();
            LDAPAttribute certs = entry.getAttribute(mCertAttr);
            LDAPAttribute subjnames = entry.getAttribute(mSubjNameAttr);

            // check if has cert already.
            if (certs != null) {
                hasCert = LdapUserCertPublisher.ByteValueExists(certs, certEnc);
            }

            // check if has subject name already.
            if (subjnames != null) {
                hasSubjname =
                        LdapUserCertPublisher.StringValueExists(subjnames, subjName);
            }

            // if has both, done.
            if (hasCert && hasSubjname) {
                log(ILogger.LL_INFO,
                        "publish: " + subjName + " already has cert & subject name");
                return;
            }

            // add cert if not already there.
            LDAPModificationSet modSet = new LDAPModificationSet();

            if (!hasCert) {
                log(ILogger.LL_INFO, "publish: adding cert to " + subjName);
                modSet.add(LDAPModification.ADD,
                        new LDAPAttribute(mCertAttr, certEnc));
            }
            // add subject name if not already there.
            if (!hasSubjname) {
                log(ILogger.LL_INFO, "publish: adding " + subjName + " to " + dn);
                modSet.add(LDAPModification.ADD,
                        new LDAPAttribute(mSubjNameAttr, subjName));
            }
            conn.modify(dn, modSet);
        } catch (CertificateEncodingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()));
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
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISHER_EXCEPTION", "", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_USERCERT_ERROR", e.toString()));
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_USERCERT_ERROR", e.toString()));
        }
    }

    /**
     * deletes the certificate from the list of certificates.
     * does not check if certificate is already there.
     * also takes out the subject name if no other certificate remain
     * with the same subject name.
     */
    public void unpublish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        try {
            boolean hasCert = false, hasSubjname = false;
            boolean hasAnotherCert = false;
            X509Certificate cert = (X509Certificate) certObj;
            String subjName = ((X500Name) cert.getSubjectDN()).toLdapDNString();

            byte[] certEnc = cert.getEncoded();

            LDAPSearchResults res =
                    conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)",
                            new String[] { mCertAttr, mSubjNameAttr }, false);

            LDAPEntry entry = res.next();
            LDAPAttribute certs = entry.getAttribute(mCertAttr);
            LDAPAttribute subjnames = entry.getAttribute(mSubjNameAttr);

            // check for cert and other certs with same subject name.
            if (certs != null) {
                hasCert = LdapUserCertPublisher.ByteValueExists(certs, certEnc);
                // check for other certs with the same subject name
                @SuppressWarnings("unchecked")
                Enumeration<byte[]> vals = certs.getByteValues();
                byte[] val = null;

                while (vals.hasMoreElements()) {
                    val = vals.nextElement();
                    if (PublisherUtils.byteArraysAreEqual(certEnc, val)) {
                        hasCert = true;
                        continue;
                    }
                    try {
                        X509CertImpl certval = new X509CertImpl(val);
                        // XXX use some sort of X500name equals function here.
                        String subjnam =
                                ((X500Name) certval.getSubjectDN()).toLdapDNString();

                        if (subjnam.equalsIgnoreCase(subjName)) {
                            hasAnotherCert = true;
                        }
                    } catch (CertificateEncodingException e) {
                        // ignore this certificate.
                        CMS.debug(
                                "LdapCertSubjPublisher: unpublish: an invalid cert in dn entry encountered");
                    } catch (CertificateException e) {
                        // ignore this certificate.
                        CMS.debug(
                                "LdapCertSubjPublisher: unpublish: an invalid cert in dn entry encountered");
                    }
                }
            }

            // check if doesn't have subject name already.
            if (subjnames != null) {
                hasSubjname =
                        LdapUserCertPublisher.StringValueExists(subjnames, subjName);
            }

            // if doesn't have both, done.
            if (!hasCert && !hasSubjname) {
                log(ILogger.LL_INFO,
                        "unpublish: " + subjName + " already has not cert & subjname");
                return;
            }

            // delete cert if there.
            LDAPModificationSet modSet = new LDAPModificationSet();

            if (hasCert) {
                log(ILogger.LL_INFO,
                        "unpublish: deleting cert " + subjName + " from " + dn);
                modSet.add(LDAPModification.DELETE,
                        new LDAPAttribute(mCertAttr, certEnc));
            }
            // delete subject name if no other cert has the same name.
            if (hasSubjname && !hasAnotherCert) {
                log(ILogger.LL_INFO,
                        "unpublish: deleting subject name " + subjName + " from " + dn);
                modSet.add(LDAPModification.DELETE,
                        new LDAPAttribute(mSubjNameAttr, subjName));
            }
            conn.modify(dn, modSet);
        } catch (CertificateEncodingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_LDAP_DN_STRING_FAILED", e.toString()));
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
                "LdapCertSubjPublisher: " + msg);
    }

}
