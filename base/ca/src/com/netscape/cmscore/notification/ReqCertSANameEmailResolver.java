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
package com.netscape.cmscore.notification;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

/**
 * An email resolver that first checks the request email, if none,
 * then follows by checking the subjectDN of the certificate, if none,
 * then follows by checking the subjectalternatename extension
 * <p>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class ReqCertSANameEmailResolver implements IEmailResolver {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ReqCertSANameEmailResolver.class);

    public static final String KEY_REQUEST = IEmailResolverKeys.KEY_REQUEST;
    public static final String KEY_CERT = IEmailResolverKeys.KEY_CERT;

    // required keys for this resolver to figure out the email address
    //	protected static String[] mRequiredKeys = {KEY_REQUEST, KEY_CERT};

    public ReqCertSANameEmailResolver() {
    }

    /**
     * returns an email address by using the resolver keys. The
     * return value can possibly be null
     *
     * @param keys list of keys used for resolving the email address
     */
    public String getEmail(IEmailResolverKeys keys)
            throws EBaseException, ENotificationException {
        IRequest req = (IRequest) keys.get(KEY_REQUEST);

        String mEmail = null;

        if (req != null) {
            mEmail = req.getExtDataInString(IRequest.HTTP_PARAMS,
                    IRequest.REQUESTOR_EMAIL);
            if (mEmail == null) {
                String mail = req.getExtDataInString("requestor_email");
                logger.info("ReqCertSANameEmailResolver: REQUESTOR_EMAIL = " + mail);
                if (mail != null && !mail.equals(""))
                    return mail;
            } else {
                if (!mEmail.equals("")) {
                    logger.info("ReqCertSANameEmailResolver: REQUESTOR_EMAIL = " + mEmail);
                    return mEmail;
                }
                logger.info("ReqCertSANameEmailResolver: REQUESTOR_EMAIL is null ");
            }
        } else {
            logger.info("ReqCertSANameEmailResolver: request null in keys");
        }
        Object request = keys.get(KEY_CERT);
        X509Certificate cert = null;

        CAEngine engine = CAEngine.getInstance();

        if (request instanceof RevokedCertImpl) {
            RevokedCertImpl revCert = (RevokedCertImpl) request;
            CertificateAuthority ca = engine.getCA();
            ICertificateRepository certDB = ca.getCertificateRepository();

            cert = certDB.getX509Certificate(revCert.getSerialNumber());
        } else
            cert = (X509Certificate) request;

        X500Name subjectDN = null;

        if (cert != null) {
            subjectDN =
                    (X500Name) cert.getSubjectDN();

            try {
                mEmail = subjectDN.getEmail();
                if (mEmail != null) {
                    if (!mEmail.equals("")) {
                        logger.info("ReqCertSANameEmailResolver: cert subjectDN E=" + mEmail);
                    }
                } else {
                    logger.info("ReqCertSANameEmailResolver: no E component in subjectDN ");
                }
            } catch (IOException e) {
                logger.error("ReqCertSANameEmailResolver: X500Name getEmail failed: " + e.getMessage(), e);
                throw new ENotificationException(
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                                subjectDN.toString()), e);
            }

            // try subjectalternatename
            if (mEmail == null) {
                X509CertInfo certInfo = null;

                logger.debug("ReqCertSANameEmailResolver: about to try subjectalternatename");
                try {
                    certInfo = (X509CertInfo)
                            ((X509CertImpl) cert).get(
                                    X509CertImpl.NAME + "." + X509CertImpl.INFO);
                } catch (CertificateParsingException ex) {
                    logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_NO_CERTINFO"), ex);
                    throw new ENotificationException(
                            CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                                    "subjectDN= " + subjectDN.toString()), ex);
                }

                CertificateExtensions exts;

                try {
                    exts = (CertificateExtensions)
                            certInfo.get(CertificateExtensions.NAME);
                } catch (IOException e) {
                    logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_GET_EXT", e.toString()), e);
                    throw new ENotificationException(
                            CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                                    "subjectDN= " + subjectDN.toString()), e);

                } catch (CertificateException e) {
                    logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_GET_EXT", e.toString()), e);
                    throw new ENotificationException(
                            CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                                    "subjectDN= " + subjectDN.toString()), e);
                }

                if (exts != null) {
                    SubjectAlternativeNameExtension ext;

                    try {
                        ext =
                                (SubjectAlternativeNameExtension)
                                exts.get(SubjectAlternativeNameExtension.NAME);
                    } catch (IOException e) {
                        logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_GET_EXT", e.toString()), e);
                        throw new ENotificationException(
                                CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                                        "subjectDN= " + subjectDN.toString()), e);

                    }

                    try {
                        if (ext != null) {
                            GeneralNames gn =
                                    (GeneralNames) ext.get(SubjectAlternativeNameExtension.SUBJECT_NAME);

                            Enumeration<GeneralNameInterface> e = gn.elements();

                            while (e.hasMoreElements()) {
                                GeneralNameInterface gni = e.nextElement();

                                if (gni.getType() == GeneralNameInterface.NAME_RFC822) {
                                    logger.debug("ReqCertSANameEmailResolver: got an subjectalternatename email");

                                    String nameString = gni.toString();

                                    // "RFC822Name: " + name
                                    mEmail =
                                            nameString.substring(nameString.indexOf(' ') + 1);
                                    logger.info("ReqCertSANameEmailResolver: subjectalternatename email used:" + mEmail);

                                    break;
                                } else {
                                    logger.warn("ReqCertSANameEmailResolver: not an subjectalternatename email");
                                }
                            }
                        }
                    } catch (IOException e) {
                        logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_SUBJECTALTNAME"), e);
                    }
                }
            }
        } else {
            logger.warn("ReqCertSANameEmailResolver: cert null in keys");
        }

        // log it
        if (mEmail == null) {
            if (cert != null) {
                logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL", subjectDN.toString()));
                logger.error("ReqCertSANameEmailResolver: no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1 for " + subjectDN);
                throw new ENotificationException(
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED", "subjectDN= " + subjectDN));
            } else if (req != null) {
                logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL_ID", req.getRequestId().toString()));
                logger.error("ReqCertSANameEmailResolver: no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1 for request id =" + req.getRequestId());
                throw new ENotificationException(
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED", "requestId= " + req.getRequestId()));
            } else {
                logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL_REQUEST"));
                logger.error("ReqCertSANameEmailResolver: no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1.  No request id or cert info found");
                throw new ENotificationException(
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED", ": No request id or cert info found"));
            }
        } else {
            logger.info("ReqCertSANameEmailResolver: email resolved: " + mEmail);
        }

        return mEmail;
    }

    /**
     * Returns array of required keys for this email resolver
     *
     * @return Array of required keys.
     */

    /*	public String[] getRequiredKeys() {
     return mRequiredKeys;
     }*/
}
