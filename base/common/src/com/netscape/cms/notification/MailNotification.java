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
package com.netscape.cms.notification;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Vector;

import netscape.net.smtp.SmtpClient;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.notification.IMailNotification;

/**
 * This class handles mail notification via SMTP.
 * This class uses <b>smtp.host</b> in the configuration for smtp
 * host. The port default (25) is used. If no smtp specified, local
 * host is used
 *
 * @version $Revision$, $Date$
 */
public class MailNotification implements IMailNotification {
    private ILogger mLogger = CMS.getLogger();
    protected final static String PROP_SMTP_SUBSTORE = "smtp";
    protected final static String PROP_HOST = "host";

    private String mHost = null;

    private String mFrom = null;
    private String mTo = null;
    private String mSubject = null;
    private String mContent = null;
    private String mContentType = null;

    public MailNotification() {
        if (mHost == null) {
            try {
                IConfigStore mConfig =
                        CMS.getConfigStore();

                IConfigStore c =
                        mConfig.getSubStore(PROP_SMTP_SUBSTORE);

                if (c == null) {
                    return;
                }
                mHost = c.getString(PROP_HOST);

                // log it
                //				if (mHost !=null) {
                //					String msg =" using external SMTP host: "+mHost;
                //					CMS.debug("MailNotification: "  + msg);
                //}
            } catch (Exception e) {
                // don't care
            }
        }
    }

    /**
     * send one message to one or more addressees
     */
    public void sendNotification() throws IOException, ENotificationException {
        // create smtp client
        SmtpClient sc = null;

        if (!mHost.equals("")) {
            sc = new SmtpClient(mHost);
        } else {
            sc = new SmtpClient();
        }

        // set "from", message subject
        if ((mFrom != null) && (!mFrom.equals("")))
            sc.from(mFrom);
        else {
            throw new ENotificationException(
                    CMS.getUserMessage("CMS_NOTIFICATION_NO_SMTP_SENDER"));
        }

        // set "to"
        if ((mTo != null) && (!mTo.equals(""))) {
            log(ILogger.LL_INFO, "mail to be sent to " + mTo);
            sc.to(mTo);
        } else {
            throw new ENotificationException(
                    CMS.getUserMessage("CMS_NOTIFICATION_NO_SMTP_RECEIVER"));
        }

        // set message content
        PrintStream msgStream = sc.startMessage();

        if (mContentType != null) {
            msgStream.print("From: " + mFrom + "\n");
            msgStream.print("MIME-Version: 1.0\n");
            msgStream.print("To: " + mTo + "\n");
            msgStream.print(mSubject + "\n");
            msgStream.print(mContentType + "\n");
        } else {
            msgStream.print("From: " + mFrom + "\n");
            msgStream.print("To: " + mTo + "\n");
            msgStream.print(mSubject + "\n");
        }
        msgStream.print("\r\n");
        msgStream.print(mContent + "\r\n");

        // send
        try {
            sc.closeServer();
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
            throw new ENotificationException(
                    CMS.getUserMessage("CMS_NOTIFICATION_SMTP_SEND_FAILED", mTo));
        }
    }

    /**
     * sets the "From" field
     *
     * @param from email address of the sender
     */
    public void setFrom(String from) {
        mFrom = from;
    }

    /**
     * sets the "Subject" field
     *
     * @param subject subject of the email
     */
    public void setSubject(String subject) {
        mSubject = "Subject: " + subject;
    }

    /**
     * sets the "Content-Type" field
     *
     * @param contentType content type of the email
     */
    public void setContentType(String contentType) {
        mContentType = "Content-Type: " + contentType;
    }

    /**
     * sets the content of the email
     *
     * @param content the message content
     */
    public void setContent(String content) {
        mContent = content;
    }

    /**
     * sets the recipients' email addresses
     *
     * @param addresses a list of email addresses of the recipients
     */
    public void setTo(Vector<String> addresses) {
        // concatenate addresses into comma separated mTo String

    }

    /**
     * sets the recipient's email address
     *
     * @param to address of the recipient email address
     */
    public void setTo(String to) {
        mTo = to;
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
                level, "MailNotification: " + msg);
    }

}
