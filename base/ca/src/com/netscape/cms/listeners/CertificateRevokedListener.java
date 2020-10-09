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

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;

import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.listeners.EListenersException;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.notification.EmailFormProcessor;
import com.netscape.cmscore.notification.EmailResolverKeys;
import com.netscape.cmscore.notification.EmailTemplate;
import com.netscape.cmscore.notification.ReqCertSANameEmailResolver;

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

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertificateRevokedListener.class);

    protected final static String PROP_CERT_ISSUED_SUBSTORE = "certRevoked";
    protected static final String PROP_ENABLED = "enabled";
    protected final static String PROP_NOTIFY_SUBSTORE = "notification";

    protected final static String PROP_SENDER_EMAIL = "senderEmail";
    protected final static String PROP_EMAIL_SUBJECT = "emailSubject";
    public final static String PROP_EMAIL_TEMPLATE = "emailTemplate";

    protected final static String REJECT_FILE_NAME = "certRequestRejected";

    private boolean mEnabled = false;
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
        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();
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
            logger.debug("CertificateRevokedListener: file separator: " + File.separator
                    +
                    " not found. Use default /");
            ridx = mFormPath.lastIndexOf("/");
            mDir = mFormPath.substring(0, ridx + 1);
        } else {
            mDir = mFormPath.substring(0, ridx +
                            File.separator.length());
        }
        logger.debug("CertificateRevokedListener: template file directory: " + mDir);
        mRejectPath = mDir + REJECT_FILE_NAME;
        if (mFormPath.endsWith(".html"))
            mRejectPath += ".html";
        else if (mFormPath.endsWith(".HTML"))
            mRejectPath += ".HTML";
        else if (mFormPath.endsWith(".htm"))
            mRejectPath += ".htm";
        else if (mFormPath.endsWith(".HTM"))
            mRejectPath += ".HTM";

        logger.debug("CertificateRevokedListener: Reject file path: " + mRejectPath);

        mDateFormat = DateFormat.getDateTimeInstance();

        mSubject_Success = rc.getString(PROP_EMAIL_SUBJECT,
                    "Your Certificate Request");
        mSubject = new String(mSubject_Success);

        // form the cert retrieval URL for the notification
        mHttpHost = cs.getHostname();
        mHttpPort = engine.getEESSLPort();

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
            logger.warn("CertificateRevokedListener: Request status: " + rs);
            //revoked(r);
            return;
        }

        // check if request failed.
        if (r.getExtDataInInteger(IRequest.RESULT) == null)
            return;

        if ((r.getExtDataInInteger(IRequest.RESULT)).equals(IRequest.RES_ERROR)) {
            logger.warn("CertificateRevokedListener: Request errored. " +
                    "No need to email notify for enrollment request id " +
                    mReqId);
            return;
        }

        if (requestType.equals(IRequest.REVOCATION_REQUEST)) {
            logger.debug("CertificateRevokedListener: accept() revocation request...");
            // Get the certificate from the request
            //X509CertImpl issuedCert[] =
            //    (X509CertImpl[])
            RevokedCertImpl crlentries[] =
                    r.getExtDataInRevokedCertArray(IRequest.CERT_INFO);

            if (crlentries != null) {
                logger.debug("CertificateRevokedListener: Sending email notification..");

                // do we have an email to send?
                String mEmail = null;
                EmailResolverKeys keys = new EmailResolverKeys();

                try {
                    keys.set(IEmailResolverKeys.KEY_REQUEST, r);
                    keys.set(IEmailResolverKeys.KEY_CERT,
                            crlentries[0]);
                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET_RESOLVER", e.toString()), e);
                }

                IEmailResolver er = new ReqCertSANameEmailResolver();

                try {
                    mEmail = er.getEmail(keys);
                } catch (ENotificationException e) {
                    logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_EXCEPTION", e.toString()), e);
                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_EXCEPTION", e.toString()), e);
                } catch (Exception e) {
                    logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_EXCEPTION", e.toString()), e);
                }

                // now we can mail
                if ((mEmail != null) && (!mEmail.equals(""))) {
                    mailIt(mEmail, crlentries);
                } else {
                    logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_NOTIFY_ERROR",
                                    crlentries[0].getSerialNumber().toString(), mReqId.toString()));
                    // send failure notification to "sender"
                    mSubject = "Certificate Issued notification undeliverable";
                    mailIt(mSenderEmail, crlentries);
                }
            }
        }
    }

    private void mailIt(String mEmail, RevokedCertImpl crlentries[]) {
        CAEngine engine = CAEngine.getInstance();
        IMailNotification mn = engine.getMailNotification();

        mn.setFrom(mSenderEmail);
        mn.setTo(mEmail);
        mn.setSubject(mSubject);

        /*
         * get template file from disk
         */
        EmailTemplate template = new EmailTemplate(mFormPath);

        /*
         * parse and process the template
         */
        if (!template.init()) {
            return;
        }

        buildContentParams(crlentries, mEmail);
        EmailFormProcessor et = new EmailFormProcessor();
        String c = et.getEmailContent(template.toString(), mContentParams);

        if (template.isHTML()) {
            mn.setContentType("text/html");
        }
        mn.setContent(c);

        try {
            mn.sendNotification();
        } catch (ENotificationException e) {
            logger.warn(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);

        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
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

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();

        try {
            RevokedCertImpl revCert = crlentries[0];
            X509Certificate cert = certDB.getX509Certificate(revCert.getSerialNumber());

            mContentParams.put(IEmailFormProcessor.TOKEN_ISSUER_DN,
                    cert.getIssuerDN().toString());
            mContentParams.put(IEmailFormProcessor.TOKEN_SUBJECT_DN,
                    cert.getSubjectDN().toString());
            Date date = crlentries[0].getRevocationDate();

            mContentParams.put(IEmailFormProcessor.TOKEN_REVOCATION_DATE,
                    mDateFormat.format(date));
        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET_RESOLVER", e.toString()), e);
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
            logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET"));
        }
    }
}
