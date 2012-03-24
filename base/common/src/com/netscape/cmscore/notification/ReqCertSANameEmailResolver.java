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


import com.netscape.certsrv.base.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.notification.*;
import java.util.Enumeration;
import java.security.*;
import java.security.cert.*;
import java.io.IOException;
import netscape.security.x509.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;


/**
 * An email resolver that first checks the request email, if none,
 * then follows by checking the subjectDN of the certificate, if none,
 * then follows by checking the subjectalternatename extension
 * <p>
 * @author cfu
 * @version $Revision$, $Date$
 */
public class ReqCertSANameEmailResolver implements IEmailResolver {
    private ILogger mLogger = CMS.getLogger();

    public static final String KEY_REQUEST = IEmailResolverKeys.KEY_REQUEST;
    public static final String KEY_CERT = IEmailResolverKeys.KEY_CERT;

    // required keys for this resolver to figure out the email address
    //	protected static String[] mRequiredKeys = {KEY_REQUEST, KEY_CERT};

    public ReqCertSANameEmailResolver() {
    }

    /**
     * returns an email address by using the resolver keys.  The
     *	 return value can possibly be null
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
                log(ILogger.LL_INFO, "REQUESTOR_EMAIL = " + mail);
                if (mail != null && !mail.equals(""))
                    return mail;
            } else {
                if (!mEmail.equals("")) {
                    log(ILogger.LL_INFO, "REQUESTOR_EMAIL = " + mEmail);
                    return mEmail;
                }
                log(ILogger.LL_INFO, "REQUESTOR_EMAIL is null ");
            }
        } else {
            log(ILogger.LL_INFO, "request null in keys");
        }
        Object request = keys.get(KEY_CERT);
        X509Certificate cert = null;

        if (request instanceof RevokedCertImpl) {
            RevokedCertImpl revCert = (RevokedCertImpl) request;
            ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            ICertificateRepository certDB = ca.getCertificateRepository();

            cert = certDB.getX509Certificate(revCert.getSerialNumber());
        }else
            cert = (X509Certificate) request;
        
        X500Name subjectDN = null;

        if (cert != null) {
            subjectDN =
                    (X500Name) cert.getSubjectDN();
			
            try {
                mEmail = subjectDN.getEmail();
                if (mEmail != null) {
                    if (!mEmail.equals("")) {
                        log(ILogger.LL_INFO, "cert subjectDN E=" +
                            mEmail);
                    }
                } else {
                    log(ILogger.LL_INFO, "no E component in subjectDN ");
                }
            } catch (IOException e) {
                System.out.println("X500Name getEmail failed");
                throw new ENotificationException (
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                        subjectDN.toString()));
            }

            // try subjectalternatename
            if (mEmail == null) {
                X509CertInfo certInfo = null;

                CMS.debug("about to try subjectalternatename");
                try {
                    certInfo = (X509CertInfo)
                            ((X509CertImpl) cert).get(
                                X509CertImpl.NAME + "." + X509CertImpl.INFO);
                } catch (CertificateParsingException ex) {
                    log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_NOTIFY_NO_CERTINFO"));
                    throw new ENotificationException (
                            CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                            "subjectDN= " + subjectDN.toString()));
                }

                CertificateExtensions exts;

                try {
                    exts = (CertificateExtensions)
                            certInfo.get(CertificateExtensions.NAME);
                } catch (IOException e) {
                    log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_NOTIFY_GET_EXT", e.toString()));
                    throw new ENotificationException (
                            CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                            "subjectDN= " + subjectDN.toString()));

                } catch (CertificateException e) {
                    log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_NOTIFY_GET_EXT", e.toString()));
                    throw new ENotificationException (
                            CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                            "subjectDN= " + subjectDN.toString()));
                }

                if (exts != null) {
                    SubjectAlternativeNameExtension ext;

                    try {
                        ext = 
                                (SubjectAlternativeNameExtension)
                                exts.get(SubjectAlternativeNameExtension.NAME);
                    } catch (IOException e) {
                        log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_NOTIFY_GET_EXT", e.toString()));
                        throw new ENotificationException (
                                CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                                "subjectDN= " + subjectDN.toString()));
						
                    }

                    try {
                        if (ext != null) {
                            GeneralNames gn =
                                (GeneralNames) ext.get(SubjectAlternativeNameExtension.SUBJECT_NAME);

                            Enumeration e = gn.elements();

                            while (e.hasMoreElements()) {
                                Object g = (Object) e.nextElement();

                                GeneralName gni =
                                    (GeneralName) g;

                                if (gni.getType() ==
                                    GeneralNameInterface.NAME_RFC822) {
                                    CMS.debug("got an subjectalternatename email");

                                    String nameString = g.toString();

                                    // "RFC822Name: " + name
                                    mEmail =
                                            nameString.substring(nameString.indexOf(' ') + 1);
                                    log(ILogger.LL_INFO,
                                        "subjectalternatename email used:" +
                                        mEmail);
									
                                    break;
                                } else {
                                    CMS.debug("not an subjectalternatename email");
                                }
                            }
                        }
                    } catch (IOException e) {
                        log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_NOTIFY_SUBJECTALTNAME"));
                    }
                }
            }
        } else {
            log(ILogger.LL_INFO, "cert null in keys");
        }
    
        // log it
        if (mEmail == null) {
            if (cert != null) {
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL", subjectDN.toString()));
                CMS.debug(
                    "no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1 for " +
                    subjectDN.toString());
                throw new ENotificationException (
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                        "subjectDN= " + subjectDN.toString()));
            } else if (req != null) {
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL_ID",
                        req.getRequestId().toString()));
                CMS.debug(
                    "no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1 for request id =" +
                    req.getRequestId().toString());
                throw new ENotificationException (
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                        "requestId= " + req.getRequestId().toString()));
            } else {
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL_REQUEST"));
                CMS.debug(
                    "no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1.  No request id or cert info found");
                throw new ENotificationException (
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                        ": No request id or cert info found"));
            }
        } else {
            log(ILogger.LL_INFO, "email resolved: " + mEmail);
        }

        return mEmail;
    }

    /**
     * Returns array of required keys for this email resolver
     * @return Array of required keys.
     */
    
    /*	public String[] getRequiredKeys() {
     return mRequiredKeys;
     }*/

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
            level, "ReqCertSANameEmailResolver: " + msg);
    }

}
