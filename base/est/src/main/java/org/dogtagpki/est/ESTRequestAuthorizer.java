//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * The EST authorization backend interface.
 *
 * @author Fraser Tweedale
 */
public abstract class ESTRequestAuthorizer {

    void start() throws Throwable { }

    void stop() throws Throwable { }

    protected ESTRequestAuthorizerConfig config;

    public void setConfig(ESTRequestAuthorizerConfig config) {
        this.config = config;
    }

    /**
     * Authorize a simpleenroll request
     *
     * @throws ForbiddenException on authorization failure
     * @throws PKIException on error
     * @return on success, an Object, which will be passed to the
     *         issuance backend (null allowed)
     */
    public abstract Object authorizeSimpleenroll(
        ESTRequestAuthorizationData data, PKCS10 csr)
            throws PKIException;

    /**
     * Authorize a simplereenroll request
     *
     * @throws ForbiddenException on authorization failure
     * @throws PKIException on error
     * @return on success, an Object, which will be passed to the
     *         issuance backend (null allowed)
     */
    public abstract Object authorizeSimplereenroll(
        ESTRequestAuthorizationData data, PKCS10 csr, X509Certificate toBeRenewed)
            throws PKIException;

    /** Ensure subject info in CSR matches the certificate.
     *
     * https://www.rfc-editor.org/rfc/rfc7030#section-4.2.2 states:
     *
     *    The request Subject field and SubjectAltName extension MUST be
     *    identical to the corresponding fields in the certificate being
     *    renewed/rekeyed.
     *
     * This function implements that requirement.
     *
     * @throws ForbiddenException if fields are not identical.
     */
    /**
     * @param csr
     * @param cert_
     * @param renew
     * @throws ForbiddenException
     */
    protected static void ensureCSRMatchesToBeCert(PKCS10 csr, X509Certificate cert_, boolean renew)
            throws ForbiddenException {
        // use a JSS X509CertImpl for easier access to the inner parts
        X509CertImpl cert;
        if (cert_ instanceof X509CertImpl) {
            cert = (X509CertImpl) cert_;
        } else {
            // construct X509CertImpl
            try {
                cert = new X509CertImpl(cert_.getEncoded());
            } catch (CertificateException e) {
                throw new ForbiddenException("Failed to decode user certificate.");
            }
        }

        // Compare Subject DNs.
        //
        // This comparison does not perform StringPrep or caseIgnoreMatch.
        // However, RFC 7030 says the values must be "identical", not "equal"
        // or "equivalent", so this seems reasonable.
        //
        // In case of new certificate the check is less strict and done after string conversion
        //
        if ((renew && !csr.getSubjectName().equals(cert.getSubjectName())) ||
                (!renew && !csr.getSubjectName().toString().equals(cert.getSubjectName().toString()))) {
            throw new ForbiddenException("CSR subject does not match user certificate.");
        }

        // Compare SAN
        SubjectAlternativeNameExtension csrSAN = null;
        try {
            csrSAN = (SubjectAlternativeNameExtension)
                CryptoUtil.getExtensionFromPKCS10(csr, SubjectAlternativeNameExtension.NAME);
        } catch (IOException | CertificateException e) {
            throw new BadRequestException("Failed to decode SAN extension in CSR.");
        }

        // TODO get SAN from t-b-r cert; compare
        SubjectAlternativeNameExtension certSAN = (SubjectAlternativeNameExtension)
            cert.getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString());

        // In case of new certificate the SAN can be missed in the CSR and
        // if present the controls are done on Strings
        if (csrSAN != null && certSAN != null) {
            if ((renew && !Arrays.equals(csrSAN.getExtensionValue(), certSAN.getExtensionValue())) ||
                    (!renew && !csrSAN.toString().equals(certSAN.toString()))) {
                throw new ForbiddenException(
                    "SAN extensions of user certificate and CSR are not identical.");
            }
        } else if (csrSAN == null && certSAN != null && renew) {
            throw new ForbiddenException(
                "User certificate has SubjectAlternativeName extension, "
                + "but CSR does not."
            );
        } else if (csrSAN != null && certSAN == null) {
            throw new ForbiddenException(
                "User certificate does not have SubjectAlternativeName extension, "
                + "but CSR does."
            );
        } // else both null, which is valid
    }

   /** Ensure subject info in CSR matches the user details.
    *
    * This function implements that requirement.
    *
    * @throws ForbiddenException if fields are not identical.
    */
   protected static void ensureCSRMatchesToBeCert(PKCS10 csr, User user)
           throws ForbiddenException {


       String subjectDn = csr.getSubjectName().toString();
       String subject = null;
       for (String sub: subjectDn.split(",")) {
           if (sub.substring(0, 3).equalsIgnoreCase("cn=")) {
               subject = sub.substring(3);
               break;
           }
           if (sub.substring(0, 4).equalsIgnoreCase("uid=")) {
               subject = sub.substring(4);
               break;
           }
       }

       if (subject == null || (!StringUtils.equalsIgnoreCase(subject, user.getFullName()) &&
               !StringUtils.equalsIgnoreCase(subject, user.getUserID()))) {
           throw new ForbiddenException("CSR subject does not match user identity. subject '" + subject + "' from dn '" + subjectDn + "'");
       }

       // Compare SAN
       SubjectAlternativeNameExtension csrSAN = null;
       try {
           csrSAN = (SubjectAlternativeNameExtension)
               CryptoUtil.getExtensionFromPKCS10(csr, SubjectAlternativeNameExtension.NAME);
       } catch (IOException | CertificateException e) {
           throw new BadRequestException("Failed to decode SAN extension in CSR.");
       }

       if (csrSAN != null) {
           for(GeneralNameInterface gName: csrSAN.getGeneralNames()) {
               String name = gName.toString().split(":")[1].trim();

               if(!StringUtils.equalsIgnoreCase(name, user.getUserID()) &&
                       !StringUtils.equalsIgnoreCase(name, user.getFullName())) {
               throw new ForbiddenException(
                       "CSR SubjectAlternativeName extension does not match user."
                       );
               }
           }
       }
   }
}
