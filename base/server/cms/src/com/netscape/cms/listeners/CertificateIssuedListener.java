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
package com.netscape.cms.listeners;

import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.util.Date;
import java.util.Hashtable;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.listeners.EListenersException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.notification.IEmailTemplate;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.RequestId;

/**
 * a listener for every completed enrollment request
 * <p>
 * Here is a list of available $TOKENs for email notification templates if certificate is successfully issued:
 * <UL>
 * <LI>$InstanceID
 * <LI>$SerialNumber
 * <LI>$HexSerialNumber
 * <LI>$HttpHost
 * <LI>$HttpPort
 * <LI>$RequestId
 * <LI>$IssuerDN
 * <LI>$SubjectDN
 * <LI>$NotBefore
 * <LI>$NotAfter
 * <LI>$SenderEmail
 * <LI>$RecipientEmail
 * </UL>
 * <p>
 * Here is a list of available $TOKENs for email notification templates if certificate request is rejected:
 * <UL>
 * <LI>$RequestId
 * <LI>$InstanceID
 * </UL>
 *
 * @version $Revision$, $Date$
 */
public class CertificateIssuedListener implements IRequestListener {
    protected final static String PROP_CERT_ISSUED_SUBSTORE = "certIssued";
    protected static final String PROP_ENABLED = "enabled";
    protected final static String PROP_NOTIFY_SUBSTORE = "notification";

    protected final static String PROP_SENDER_EMAIL = "senderEmail";
    protected final static String PROP_EMAIL_SUBJECT = "emailSubject";
    public final static String PROP_EMAIL_TEMPLATE = "emailTemplate";

    protected final static String REJECT_FILE_NAME = "certRequestRejected";

    private boolean mEnabled = false;
    private ILogger mLogger = CMS.getLogger();
    private String mSenderEmail = null;
    private String mSubject = null;
    private String mSubject_Success = null;
    private String mFormPath = null;
    private String mRejectPath = null;
    private Hashtable<String, Object> mContentParams = new Hashtable<String, Object>();

    private IConfigStore mConfig = null;
    private DateFormat mDateFormat = null;
    private ICertAuthority mSubsystem = null;
    private String mHttpHost = null;
    private String mHttpPort = null;
    private RequestId mReqId = null;

    public CertificateIssuedListener() {
    }

    public void init(ISubsystem sub, IConfigStore config)
            throws EListenersException, EPropertyNotFound, EBaseException {
        mSubsystem = (ICertAuthority) sub;
        mConfig = mSubsystem.getConfigStore();

        IConfigStore nc = mConfig.getSubStore(PROP_NOTIFY_SUBSTORE);
        IConfigStore rc = nc.getSubStore(PROP_CERT_ISSUED_SUBSTORE);

        mEnabled = rc.getBoolean(PROP_ENABLED, false);

        mSenderEmail = rc.getString(PROP_SENDER_EMAIL);
        if (mSenderEmail == null) {
            throw new EListenersException(CMS.getLogMessage("NO_NOTIFY_SENDER_EMAIL_CONFIG_FOUND"));
        }

        mFormPath = rc.getString(PROP_EMAIL_TEMPLATE);
        String mDir = null;

        // figure out the reject email path: same dir as form path,
        //		same ending as form path
        int ridx = mFormPath.lastIndexOf(File.separator);

        if (ridx == -1) {
            CMS.debug("CertificateIssuedListener: file separator: " + File.separator
                    +
                    " not found. Use default /");
            ridx = mFormPath.lastIndexOf("/");
            mDir = mFormPath.substring(0, ridx + 1);
        } else {
            mDir = mFormPath.substring(0, ridx +
                            File.separator.length());
        }
        CMS.debug("CertificateIssuedListener: template file directory: " + mDir);
        mRejectPath = mDir + REJECT_FILE_NAME;
        if (mFormPath.endsWith(".html"))
            mRejectPath += ".html";
        else if (mFormPath.endsWith(".HTML"))
            mRejectPath += ".HTML";
        else if (mFormPath.endsWith(".htm"))
            mRejectPath += ".htm";
        else if (mFormPath.endsWith(".HTM"))
            mRejectPath += ".HTM";

        CMS.debug("CertificateIssuedListener: Reject file path: " + mRejectPath);

        mDateFormat = DateFormat.getDateTimeInstance();

        mSubject_Success = rc.getString(PROP_EMAIL_SUBJECT,
                    "Your Certificate Request");
        mSubject = new String(mSubject_Success);

        // form the cert retrieval URL for the notification
        mHttpHost = CMS.getEEHost();
        mHttpPort = CMS.getEESSLPort();

        // register for this event listener
        mSubsystem.registerRequestListener(this);
    }

    public void accept(IRequest r) {
        CMS.debug("CertificateIssuedListener: accept " +
                r.getRequestId().toString());
        if (mEnabled != true)
            return;

        mSubject = mSubject_Success;
        mReqId = r.getRequestId();
        // is it rejected?
        String rs = r.getRequestStatus().toString();

        if (rs.equals("rejected")) {
            CMS.debug("CertificateIssuedListener: Request status: " + rs);
            rejected(r);
            return;
        }

        CMS.debug("CertificateIssuedListener: accept check status ");

        // check if it is profile request
        String profileId = r.getExtDataInString("profileId");

        // check if request failed.
        if (profileId == null) {
            if (r.getExtDataInInteger(IRequest.RESULT) == null)
                return;
            if ((r.getExtDataInInteger(IRequest.RESULT)).equals(IRequest.RES_ERROR)) {
                CMS.debug("CertificateIssuedListener: Request errored. " +
                        "No need to email notify for enrollment request id " +
                        mReqId);
                return;
            }
        }
        String requestType = r.getRequestType();

        if (requestType.equals(IRequest.ENROLLMENT_REQUEST) ||
                requestType.equals(IRequest.RENEWAL_REQUEST)) {
            CMS.debug("accept() enrollment/renewal request...");
            // Get the certificate from the request
            X509CertImpl issuedCert[] = null;

            // handle profile-based enrollment's notification
            if (profileId == null) {
                issuedCert = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);
            } else {
                issuedCert = new X509CertImpl[1];
                issuedCert[0] =
                        r.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
            }

            if (issuedCert != null) {
                CMS.debug("CertificateIssuedListener: Sending email notification..");

                // do we have an email to send?
                String mEmail = null;
                IEmailResolverKeys keys = CMS.getEmailResolverKeys();

                try {
                    keys.set(IEmailResolverKeys.KEY_REQUEST, r);
                    keys.set(IEmailResolverKeys.KEY_CERT,
                            issuedCert[0]);
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET_RESOLVER", e.toString()));
                }

                IEmailResolver er = CMS.getReqCertSANameEmailResolver();

                try {
                    mEmail = er.getEmail(keys);
                } catch (ENotificationException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("LISTENERS_CERT_ISSUED_EXCEPTION",
                                    e.toString()));
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("LISTENERS_CERT_ISSUED_EXCEPTION",
                                    e.toString()));
                } catch (Exception e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("LISTENERS_CERT_ISSUED_EXCEPTION",
                                    e.toString()));
                }

                // now we can mail
                if ((mEmail != null) && (!mEmail.equals(""))) {
                    mailIt(mEmail, issuedCert);
                } else {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("LISTENERS_CERT_ISSUED_NOTIFY_ERROR",
                                    issuedCert[0].getSerialNumber().toString(), mReqId.toString()));
                    // send failure notification to "sender"
                    mSubject = "Certificate Issued notification undeliverable";
                    mailIt(mSenderEmail, issuedCert);
                }
            }
        }
    }

    private void mailIt(String mEmail, X509CertImpl issuedCert[]) {
        IMailNotification mn = CMS.getMailNotification();

        mn.setFrom(mSenderEmail);
        mn.setTo(mEmail);
        mn.setSubject(mSubject);

        /*
         * get template file from disk
         */
        IEmailTemplate template = CMS.getEmailTemplate(mFormPath);

        /*
         * parse and process the template
         */
        if (template != null) {
            if (!template.init()) {
                return;
            }

            buildContentParams(issuedCert, mEmail);
            IEmailFormProcessor et = CMS.getEmailFormProcessor();
            String c = et.getEmailContent(template.toString(), mContentParams);

            if (template.isHTML()) {
                mn.setContentType("text/html");
            }
            mn.setContent(c);
        } else {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("LISTENERS_CERT_ISSUED_TEMPLATE_ERROR",
                            issuedCert[0].getSerialNumber().toString(), mReqId.toString()));

            mn.setContent("Serial Number = " +
                    issuedCert[0].getSerialNumber() +
                    "; Request ID = " + mReqId);
        }

        try {
            mn.sendNotification();
        } catch (ENotificationException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));

        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
        }
    }

    private void rejected(IRequest r) {
        // do we have an email to send?
        String mEmail = null;
        IEmailResolverKeys keys = CMS.getEmailResolverKeys();

        try {
            keys.set(IEmailResolverKeys.KEY_REQUEST, r);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET_RESOLVER", e.toString()));
        }

        IEmailResolver er = CMS.getReqCertSANameEmailResolver();

        try {
            mEmail = er.getEmail(keys);
        } catch (ENotificationException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
        }

        // now we can mail
        if ((mEmail != null) && !mEmail.equals("")) {
            IMailNotification mn = CMS.getMailNotification();

            mn.setFrom(mSenderEmail);
            mn.setTo(mEmail);
            mn.setSubject(mSubject);

            /*
             * get rejection file from disk
             */
            IEmailTemplate template = CMS.getEmailTemplate(mRejectPath);

            if (template != null) {
                if (!template.init()) {
                    return;
                }

                if (template.isHTML()) {
                    mn.setContentType("text/html");
                }

                // build some token data
                mContentParams.put(IEmailFormProcessor.TOKEN_ID, mConfig.getName());
                mReqId = r.getRequestId();
                mContentParams.put(IEmailFormProcessor.TOKEN_REQUEST_ID,
                        mReqId.toString());
                IEmailFormProcessor et = CMS.getEmailFormProcessor();
                String c = et.getEmailContent(template.toString(), mContentParams);

                mn.setContent(c);
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("LISTENERS_CERT_ISSUED_REJECTION"));
                mn.setContent("Your Certificate Request has been rejected.  Please contact your administrator for assistance");
            }

            try {
                mn.sendNotification();
            } catch (ENotificationException e) {
                // already logged, lets audit
                log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));

            } catch (IOException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
            }
        } else {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("LISTENERS_CERT_ISSUED_REJECTION_NOTIFICATION", mReqId.toString()));

        }
    }

    private void buildContentParams(X509CertImpl issuedCert[], String mEmail) {
        mContentParams.put(IEmailFormProcessor.TOKEN_ID,
                mConfig.getName());
        mContentParams.put(IEmailFormProcessor.TOKEN_SERIAL_NUM,
                issuedCert[0].getSerialNumber().toString());
        mContentParams.put(IEmailFormProcessor.TOKEN_HEX_SERIAL_NUM,
                Long.toHexString(issuedCert[0].getSerialNumber().longValue()));
        mContentParams.put(IEmailFormProcessor.TOKEN_REQUEST_ID,
                mReqId.toString());
        mContentParams.put(IEmailFormProcessor.TOKEN_HTTP_HOST,
                mHttpHost);
        mContentParams.put(IEmailFormProcessor.TOKEN_HTTP_PORT,
                mHttpPort);
        mContentParams.put(IEmailFormProcessor.TOKEN_ISSUER_DN,
                issuedCert[0].getIssuerDN().toString());
        mContentParams.put(IEmailFormProcessor.TOKEN_SUBJECT_DN,
                issuedCert[0].getSubjectDN().toString());

        Date date = issuedCert[0].getNotAfter();

        mContentParams.put(IEmailFormProcessor.TOKEN_NOT_AFTER,
                mDateFormat.format(date));

        date = issuedCert[0].getNotBefore();
        mContentParams.put(IEmailFormProcessor.TOKEN_NOT_BEFORE,
                mDateFormat.format(date));

        mContentParams.put(IEmailFormProcessor.TOKEN_SENDER_EMAIL,
                mSenderEmail);
        mContentParams.put(IEmailFormProcessor.TOKEN_RECIPIENT_EMAIL,
                mEmail);
        // ... and more
    }

    /**
     * sets the configurable parameters
     */
    public void set(String name, String val) {
        if (name.equalsIgnoreCase(PROP_ENABLED)) {
            if (val.equalsIgnoreCase("true")) {
                mEnabled = true;
            } else {
                mEnabled = false;
            }
        } else if (name.equalsIgnoreCase(PROP_SENDER_EMAIL)) {
            mSenderEmail = val;
        } else if (name.equalsIgnoreCase(PROP_EMAIL_SUBJECT)) {
            mSubject_Success = val;
            mSubject = mSubject_Success;
        } else if (name.equalsIgnoreCase(PROP_EMAIL_TEMPLATE)) {
            mFormPath = val;
        } else {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET"));
        }
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
                level, msg);
    }

}
