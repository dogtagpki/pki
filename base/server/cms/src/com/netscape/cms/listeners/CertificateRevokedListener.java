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
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.Hashtable;

import netscape.security.x509.RevokedCertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.listeners.EListenersException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.notification.IEmailTemplate;
import com.netscape.certsrv.notification.IMailNotification;
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
 * Here is a list of available $TOKENs for email notification templates if certificate request is revoked:
 * <UL>
 * <LI>$RequestId
 * <LI>$InstanceID
 * </UL>
 *
 * @version $Revision$, $Date$
 */
public class CertificateRevokedListener implements IRequestListener {
    protected final static String PROP_CERT_ISSUED_SUBSTORE = "certRevoked";
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

    public CertificateRevokedListener() {
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
            CMS.debug("CertificateRevokedListener: file separator: " + File.separator
                    +
                    " not found. Use default /");
            ridx = mFormPath.lastIndexOf("/");
            mDir = mFormPath.substring(0, ridx + 1);
        } else {
            mDir = mFormPath.substring(0, ridx +
                            File.separator.length());
        }
        CMS.debug("CertificateRevokedListener: template file directory: " + mDir);
        mRejectPath = mDir + REJECT_FILE_NAME;
        if (mFormPath.endsWith(".html"))
            mRejectPath += ".html";
        else if (mFormPath.endsWith(".HTML"))
            mRejectPath += ".HTML";
        else if (mFormPath.endsWith(".htm"))
            mRejectPath += ".htm";
        else if (mFormPath.endsWith(".HTM"))
            mRejectPath += ".HTM";

        CMS.debug("CertificateRevokedListener: Reject file path: " + mRejectPath);

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
        if (mEnabled != true)
            return;

        mSubject = mSubject_Success;
        mReqId = r.getRequestId();
        // is it revoked?
        String rs = r.getRequestStatus().toString();
        String requestType = r.getRequestType();

        if (requestType.equals(IRequest.REVOCATION_REQUEST) == false)
            return;
        if (rs.equals("complete") == false) {
            CMS.debug("CertificateRevokedListener: Request status: " + rs);
            //revoked(r);
            return;
        }

        // check if request failed.
        if (r.getExtDataInInteger(IRequest.RESULT) == null)
            return;

        if ((r.getExtDataInInteger(IRequest.RESULT)).equals(IRequest.RES_ERROR)) {
            CMS.debug("CertificateRevokedListener: Request errored. " +
                    "No need to email notify for enrollment request id " +
                    mReqId);
            return;
        }

        if (requestType.equals(IRequest.REVOCATION_REQUEST)) {
            CMS.debug("CertificateRevokedListener: accept() revocation request...");
            // Get the certificate from the request
            //X509CertImpl issuedCert[] =
            //    (X509CertImpl[])
            RevokedCertImpl crlentries[] =
                    r.getExtDataInRevokedCertArray(IRequest.CERT_INFO);

            if (crlentries != null) {
                CMS.debug("CertificateRevokedListener: Sending email notification..");

                // do we have an email to send?
                String mEmail = null;
                IEmailResolverKeys keys = CMS.getEmailResolverKeys();

                try {
                    keys.set(IEmailResolverKeys.KEY_REQUEST, r);
                    keys.set(IEmailResolverKeys.KEY_CERT,
                            crlentries[0]);
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
                    mailIt(mEmail, crlentries);
                } else {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("LISTENERS_CERT_ISSUED_NOTIFY_ERROR",
                                    crlentries[0].getSerialNumber().toString(), mReqId.toString()));
                    // send failure notification to "sender"
                    mSubject = "Certificate Issued notification undeliverable";
                    mailIt(mSenderEmail, crlentries);
                }
            }
        }
    }

    private void mailIt(String mEmail, RevokedCertImpl crlentries[]) {
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

            buildContentParams(crlentries, mEmail);
            IEmailFormProcessor et = CMS.getEmailFormProcessor();
            String c = et.getEmailContent(template.toString(), mContentParams);

            if (template.isHTML()) {
                mn.setContentType("text/html");
            }
            mn.setContent(c);
        } else {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("LISTENERS_CERT_ISSUED_TEMPLATE_ERROR",
                            crlentries[0].getSerialNumber().toString(), mReqId.toString()));

            mn.setContent("Serial Number = " +
                    crlentries[0].getSerialNumber() +
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

    private void buildContentParams(RevokedCertImpl crlentries[], String mEmail) {
        mContentParams.put(IEmailFormProcessor.TOKEN_ID,
                mConfig.getName());
        mContentParams.put(IEmailFormProcessor.TOKEN_SERIAL_NUM,
                crlentries[0].getSerialNumber().toString());
        mContentParams.put(IEmailFormProcessor.TOKEN_HEX_SERIAL_NUM,
                Long.toHexString(crlentries[0].getSerialNumber().longValue()));
        mContentParams.put(IEmailFormProcessor.TOKEN_REQUEST_ID,
                mReqId.toString());
        mContentParams.put(IEmailFormProcessor.TOKEN_HTTP_HOST,
                mHttpHost);
        mContentParams.put(IEmailFormProcessor.TOKEN_HTTP_PORT,
                mHttpPort);

        try {
            RevokedCertImpl revCert = crlentries[0];
            ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            ICertificateRepository certDB = ca.getCertificateRepository();
            X509Certificate cert = certDB.getX509Certificate(revCert.getSerialNumber());

            mContentParams.put(IEmailFormProcessor.TOKEN_ISSUER_DN,
                    cert.getIssuerDN().toString());
            mContentParams.put(IEmailFormProcessor.TOKEN_SUBJECT_DN,
                    cert.getSubjectDN().toString());
            Date date = crlentries[0].getRevocationDate();

            mContentParams.put(IEmailFormProcessor.TOKEN_REVOCATION_DATE,
                    mDateFormat.format(date));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET_RESOLVER", e.toString()));
        }

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
