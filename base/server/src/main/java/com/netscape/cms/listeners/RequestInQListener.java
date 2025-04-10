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

import java.io.IOException;
import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.listeners.EListenersException;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cms.notification.MailNotification;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.notification.EmailFormProcessor;
import com.netscape.cmscore.notification.EmailTemplate;
import com.netscape.cmscore.request.Request;

/**
 * a listener for every request gets into the request queue.
 *
 * Here is a list of available $TOKENs for email notification templates:
 * <UL>
 * <LI>$RequestorEmail
 * <LI>$CertType
 * <LI>$RequestType
 * <LI>$RequestId
 * <LI>$HttpHost
 * <LI>$HttpPort
 * <LI>$SenderEmail
 * <LI>$RecipientEmail
 * </UL>
 */
public class RequestInQListener extends RequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestInQListener.class);

    protected static final String PROP_ENABLED = "enabled";
    protected final static String PROP_SENDER_EMAIL = "senderEmail";
    protected final static String PROP_RECVR_EMAIL = "recipientEmail";
    public final static String PROP_EMAIL_TEMPLATE = "emailTemplate";
    protected static final String PROP_EMAIL_SUBJECT = "emailSubject";

    protected final static String PROP_NOTIFY_SUBSTORE = "notification";
    protected final static String PROP_REQ_IN_Q_SUBSTORE = "requestInQ";

    private boolean mEnabled = false;
    private String mSenderEmail = null;
    private String mRecipientEmail = null;
    private String mEmailSubject = null;
    private String mFormPath = null;
    protected ConfigStore mConfig;
    private Hashtable<String, Object> mContentParams = new Hashtable<>();
    private String mId = "RequestInQListener";
    private String mHttpHost = null;
    private String mAgentPort = null;

    /**
     * Constructor
     */
    public RequestInQListener() {
    }

    /**
     * initializes the listener from the configuration
     */
    @Override
    public void init(Subsystem sub, ConfigStore config) throws EBaseException {

        logger.info("RequestInQListener: Initializing RequestInQListener");

        EngineConfig cs = engine.getConfig();
        if (sub != null) {
            mConfig = sub.getConfigStore();
        }

        ConfigStore nc = mConfig.getSubStore(PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        ConfigStore rq = nc.getSubStore(PROP_REQ_IN_Q_SUBSTORE, ConfigStore.class);

        mEnabled = rq.getBoolean(PROP_ENABLED, false);
        logger.info("RequestInQListener: - enabled: " + mEnabled);

        mSenderEmail = rq.getString(PROP_SENDER_EMAIL);
        logger.info("RequestInQListener: - sender email: " + mSenderEmail);

        if (mSenderEmail == null) {
            throw new EListenersException(CMS.getLogMessage("NO_NOTIFY_SENDER_EMAIL_CONFIG_FOUND"));
        }

        mRecipientEmail = rq.getString(PROP_RECVR_EMAIL);
        logger.info("RequestInQListener: - recipient email: " + mRecipientEmail);

        if (mRecipientEmail == null) {
            throw new EListenersException(CMS.getLogMessage("NO_NOTIFY_RECVR_EMAIL_CONFIG_FOUND"));
        }

        mEmailSubject = rq.getString(PROP_EMAIL_SUBJECT);
        if (mEmailSubject == null) {
            mEmailSubject = "Request in Queue";
        }
        logger.info("RequestInQListener: - email subject: " + mEmailSubject);

        mFormPath = rq.getString(PROP_EMAIL_TEMPLATE);
        logger.info("RequestInQListener: - email template: " + mFormPath);

        // make available http host and port for forming url in templates
        mHttpHost = cs.getHostname();
        mAgentPort = engine.getAgentPort();
        if (mAgentPort == null)
            logger.error(CMS.getLogMessage("LISTENERS_REQUEST_PORT_NOT_FOUND"));
        else
            logger.debug("RequestInQuListener: agentport = " + mAgentPort);

        // register for this event listener
        engine.registerPendingListener(this);
    }

    /**
     * carries out the operation when the listener is triggered.
     *
     * @param r Request structure holding the request information
     * @see com.netscape.cmscore.request.Request
     */
    @Override
    public void accept(Request r) {

        logger.info("RequestInQListener: Accepting request " + r.getRequestId().toHexString());

        if (mEnabled != true)
            return;

        // regardless of type of request...notify for everything
        // no need for email resolver here...
        MailNotification mn = engine.getMailNotification();

        mn.setFrom(mSenderEmail);
        mn.setTo(mRecipientEmail);
        mn.setSubject(mEmailSubject + " (request id: " +
                r.getRequestId().toHexString() + ")");

        /*
         * get form file from disk
         */
        EmailTemplate template = new EmailTemplate(mFormPath);

        /*
         * parse and process the template
         */
        if (!template.init()) {
            logger.warn(CMS.getLogMessage("LISTENERS_TEMPLATE_NOT_INIT"));
            return;
        }

        buildContentParams(r);
        EmailFormProcessor et = new EmailFormProcessor();
        String c = et.getEmailContent(template.toString(), mContentParams);

        if (template.isHTML()) {
            mn.setContentType("text/html");
        }
        mn.setContent(c);

        logger.info("RequestInQListener: Sending notification to " + mRecipientEmail);

        try {
            mn.sendNotification();
        } catch (ENotificationException e) {
            logger.warn(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            logger.warn(CMS.getLogMessage("LISTENERS_SEND_FAILED", e.toString()));

        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("LISTENERS_SEND_FAILED", e.toString()), e);
        }
    }

    protected Object getRequestorEmail(Request r) {
        return r.getExtDataInString(Request.HTTP_PARAMS, "csrRequestorEmail");
    }

    protected Object getCertType(Request r) {
        return r.getExtDataInString(Request.HTTP_PARAMS, Request.CERT_TYPE);
    }

    private void buildContentParams(Request r) {
        mContentParams.clear();
        mContentParams.put(EmailFormProcessor.TOKEN_ID, mConfig.getName());
        Object val = null;

        val = getRequestorEmail(r);
        if (val != null) {
            mContentParams.put(EmailFormProcessor.TOKEN_REQUESTOR_EMAIL, val);
        }

        val = getCertType(r);
        if (val != null) {
            mContentParams.put(EmailFormProcessor.TOKEN_CERT_TYPE, val);
        }

        RequestId reqId = r.getRequestId();

        mContentParams.put(EmailFormProcessor.TOKEN_REQUEST_ID, reqId.toHexString());
        mContentParams.put(EmailFormProcessor.TOKEN_ID, mId);

        val = r.getRequestType();
        if (val != null) {
            mContentParams.put(EmailFormProcessor.TOKEN_REQUEST_TYPE, val);
        }

        mContentParams.put(EmailFormProcessor.TOKEN_HTTP_HOST, mHttpHost);
        mContentParams.put(EmailFormProcessor.TOKEN_HTTP_PORT, mAgentPort);

        mContentParams.put(EmailFormProcessor.TOKEN_SENDER_EMAIL, mSenderEmail);
        mContentParams.put(EmailFormProcessor.TOKEN_RECIPIENT_EMAIL, mRecipientEmail);
    }

    /**
     * sets the configurable parameters
     *
     * @param name a String represents the name of the configuration parameter to be set
     * @param val a String containing the value to be set for name
     */
    @Override
    public void set(String name, String val) {
        if (name.equalsIgnoreCase(PROP_ENABLED)) {
            if (val.equalsIgnoreCase("true")) {
                mEnabled = true;
            } else {
                mEnabled = false;
            }
        } else if (name.equalsIgnoreCase(PROP_SENDER_EMAIL)) {
            mSenderEmail = val;
        } else if (name.equalsIgnoreCase(PROP_RECVR_EMAIL)) {
            mRecipientEmail = val;
        } else if (name.equalsIgnoreCase(PROP_EMAIL_SUBJECT)) {
            mEmailSubject = val;
        } else if (name.equalsIgnoreCase(PROP_EMAIL_TEMPLATE)) {
            mFormPath = val;
        } else {
            logger.warn(CMS.getLogMessage("LISTENERS_CERT_ISSUED_SET"));
        }
    }
}
