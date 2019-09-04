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
import java.security.cert.X509Certificate;

import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

/**
 * An email resolver that first checks the request email, if none,
 * then follows by checking the subjectDN of the certificate
 * <p>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class ReqCertEmailResolver implements IEmailResolver {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ReqCertEmailResolver.class);

    public static final String KEY_REQUEST = "request";
    public static final String KEY_CERT = "cert";

    // required keys for this resolver to figure out the email address
    //	protected static String[] mRequiredKeys = {KEY_REQUEST, KEY_CERT};

    public ReqCertEmailResolver() {
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
                    "csrRequestorEmail");
            if (mEmail == null) {
                String mail = req.getExtDataInString("requestor_email");
                logger.info("ReqCertEmailResolver: REQUESTOR_EMAIL = " + mail);
                if (mail != null && !mail.equals(""))
                    return mail;
            } else {
                if (!mEmail.equals(""))
                    return mEmail;
            }
        } else {
            logger.warn("ReqCertEmailResolver: request null in keys");
        }

        X509Certificate cert = (X509Certificate) keys.get(KEY_CERT);

        X500Name subjectDN = null;

        if (cert != null) {
            subjectDN =
                    (X500Name) cert.getSubjectDN();

            try {
                mEmail = subjectDN.getEmail();
            } catch (IOException e) {
                System.out.println("X500Name getEmail failed");
                throw new ENotificationException(
                        CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED",
                                subjectDN.toString()));
            }
        } else {
            logger.warn("ReqCertEmailResolver: cert null in keys");
        }

        // log it
        if (mEmail == null) {
            if (cert != null) {
                logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL", subjectDN.toString()));
                logger.error("ReqCertEmailResolver: no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1 for " + subjectDN);
                throw new ENotificationException(CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED", "subjectDN= " + subjectDN));

            } else if (req != null) {
                logger.error("ReqCertEmailResolver: no email resolved for request id =" + req.getRequestId());
                logger.error("ReqCertEmailResolver: throwing NotificationResources.EMAIL_RESOLVE_FAILED_1");
                throw new ENotificationException(CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED", "requestId= " + req.getRequestId()));

            } else {
                logger.error(CMS.getLogMessage("CMSCORE_NOTIFY_NO_EMAIL_REQUEST"));
                logger.error("ReqCertEmailResolver: no email resolved, throwing NotificationResources.EMAIL_RESOLVE_FAILED_1.  No request id or cert info found");
                throw new ENotificationException(CMS.getUserMessage("CMS_NOTIFICATION_EMAIL_RESOLVE_FAILED", ": No request id or cert info found"));
            }
        } else {
            logger.info("ReqCertEmailResolver: email resolved: " + mEmail);
        }

        return mEmail;
    }

    /**
     * Returns array of required keys for this email resolver
     *
     * @return Array of required keys.
     */
}
