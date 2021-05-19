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
package com.netscape.cms.jobs;

import java.text.DateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.jobs.IJobCron;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.notification.EmailFormProcessor;
import com.netscape.cmscore.request.ARequestQueue;
import com.netscape.cmscore.request.RequestRepository;

/**
 * a job for the Jobs Scheduler. This job checks in the internal ldap
 * db for certs that have expired and remove them from the ldap
 * publishing directory.
 * <p>
 * the $TOKENS that are available for the this jobs's summary outer form are:<br>
 * <UL>
 * $Status $InstanceID $SummaryItemList $SummaryTotalNum $SummaryTotalSuccess $SummaryTotalfailure $ExecutionTime
 * </UL>
 * and for the inner list items:
 * <UL>
 * $SerialNumber $IssuerDN $SubjectDN $NotAfter $NotBefore $RequestorEmail $CertType
 * </UL>
 *
 * @version $Revision$, $Date$
 */
public class UnpublishExpiredJob extends AJobBase
        implements IExtendedPluginInfo {

    CertificateAuthority mCa;
    RequestRepository requestRepository;
    ARequestQueue mReqQ = null;
    CertificateRepository mRepository;
    CAPublisherProcessor mPublisherProcessor;
    private boolean mSummary = false;

    /* Holds configuration parameters accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams =
            new String[] {
                    "enabled",
                    "cron",
                    "summary.enabled",
                    "summary.emailSubject",
                    "summary.emailTemplate",
                    "summary.itemTemplate",
                    "summary.senderEmail",
                    "summary.recipientEmail"
        };

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
        String s[] = {
                IExtendedPluginInfo.HELP_TEXT +
                        "; A job that checks for expired certificates in the " +
                        "database, and removes them from the publishing " +
                        "directory",
                "cron;string;Format: minute hour dayOfMonth month " +
                        "dayOfWeek. Use '*' for 'every'. For dayOfWeek, 0 is Sunday",
                "summary.senderEmail;string;Specify the address to be used " +
                        "as the email's 'sender'. Bounces go to this address.",
                "summary.recipientEmail;string;Who should receive summaries",
                "enabled;boolean;Enable this plugin",
                "summary.enabled;boolean;Enable the summary. You must enabled " +
                        "this for the job to work.",
                "summary.emailSubject;string;Subject of summary email",
                "summary.emailTemplate;string;Fully qualified pathname of " +
                        "template file of email to be sent",
                "summary.itemTemplate;string;Fully qualified pathname of " +
                        "file containing template for each item",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-jobrules-unpublishexpiredjobs",
            };

        return s;
    }

    /**
     * initialize from the configuration file
     */
    @Override
    public void init(ISubsystem owner, String id, String implName, IConfigStore config) throws
            EBaseException {
        mConfig = config;
        mId = id;
        mImplName = implName;

        CAEngine engine = CAEngine.getInstance();
        mCa = engine.getCA();
        requestRepository = engine.getRequestRepository();
        mReqQ = engine.getRequestQueue();
        mRepository = engine.getCertificateRepository();
        mPublisherProcessor = engine.getPublisherProcessor();

        // read from the configuration file
        mCron = mConfig.getString(IJobCron.PROP_CRON);
        if (mCron == null) {
            return;
        }

        // parse cron string into a JobCron class
        JobsScheduler scheduler = (JobsScheduler) owner;

        mJobCron = scheduler.createJobCron(mCron);

        // initialize the summary related config info
        IConfigStore sc = mConfig.getSubStore(PROP_SUMMARY);

        if (sc.getBoolean(PROP_ENABLED, false)) {
            mSummary = true;
            mSummaryMailSubject = sc.getString(PROP_EMAIL_SUBJECT);
            mMailForm = sc.getString(PROP_EMAIL_TEMPLATE);
            mItemForm = sc.getString(PROP_ITEM_TEMPLATE);
            mSummarySenderEmail = sc.getString(PROP_SENDER_EMAIL);
            mSummaryReceiverEmail = sc.getString(PROP_RECEIVER_EMAIL);
        } else {
            mSummary = false;
        }
    }

    /**
     * look in the internal db for certificateRecords that are
     * expired.
     * remove them from ldap publishing directory
     * if remove successfully, mark <i>false</i> on the
     * <b>InLdapPublishDir</b> flag,
     * else, if remove unsuccessfully, log it
     */
    @Override
    public void run() {
        //		System.out.println("in ExpiredUnpublishJob "+
        //						   getId()+ " : run()");
        // get time now..."now" is before the loop
        Date date = new Date();
        long now = date.getTime();
        DateFormat dateFormat = DateFormat.getDateTimeInstance();
        String nowString = dateFormat.format(date);

        // form filter
        String filter = "(&(x509Cert.notAfter<=" + now +
                ")(!(x509Cert.notAfter=" + now + "))" +
                "(" + "certMetainfo=" + CertRecord.META_LDAPPUBLISH +
                ":true))";
        // a test for without CertRecord.META_LDAPPUBLISH
        //String filter = "(x509Cert.notAfter<="+ now +")";

        Enumeration<Object> expired = null;

        try {
            expired = mRepository.findCertRecs(filter);
            // bug 399150
            /*
             CertRecordList list = null;
             list = mRepository.findCertRecordsInList(filter,  null, "serialno", 5);
             int size = list.getSize();
             expired = list.getCertRecords(0, size - 1);
             */
        } catch (EBaseException e) {
            logger.warn("UnpublishExpiredJob: " + CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
        }

        int count = 0; // how many have been unpublished successfully
        int negCount = 0; // how many have NOT been unpublished successfully
        String contentForm = null;
        String itemForm = null;
        String itemListContent = null;

        if (mSummary == true) {
            contentForm = getTemplateContent(mMailForm);
            itemForm = getTemplateContent(mItemForm);
        }

        // unpublish them and unpublish() will set inLdapPublishDir flag
        while (expired != null && expired.hasMoreElements()) {
            CertRecord rec = (CertRecord) expired.nextElement();

            if (rec == null)
                break;
            X509CertImpl cert = rec.getCertificate();

            if (mSummary == true)
                buildItemParams(cert);

            // get request id from cert record MetaInfo
            MetaInfo minfo = null;

            try {
                minfo = (MetaInfo) rec.get(CertRecord.ATTR_META_INFO);
            } catch (EBaseException e) {
                negCount += 1;
                if (mSummary == true)
                    buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                            STATUS_FAILURE);
                logger.warn("UnpublishExpiredJob: " + CMS.getLogMessage("JOBS_META_INFO_ERROR",
                                cert.getSerialNumber().toString(16) + e.getMessage()), e);
            }

            String ridString = null;

            try {
                if (minfo != null)
                    ridString = (String) minfo.get(CertRecord.META_REQUEST_ID);
            } catch (EBaseException e) {
                negCount += 1;
                if (mSummary == true)
                    buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                            STATUS_FAILURE);
                logger.warn("UnpublishExpiredJob: " + CMS.getLogMessage("JOBS_META_REQUEST_ERROR",
                                cert.getSerialNumber().toString(16) + e.getMessage()), e);
            } catch (NullPointerException e) {
                // no requestId in MetaInfo...skip to next record
                negCount += 1;
                if (mSummary == true)
                    buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                            STATUS_FAILURE);
                logger.warn("UnpublishExpiredJob: " + CMS.getLogMessage("JOBS_META_REQUEST_ERROR",
                                cert.getSerialNumber().toString(16) + e.getMessage()), e);
            }

            if (ridString != null) {
                RequestId rid = new RequestId(ridString);

                // get request from request id
                IRequest req = null;

                try {
                    req = requestRepository.readRequest(rid);
                    if (req != null) {
                        if (mSummary == true)
                            buildItemParams(req);
                    }
                } catch (EBaseException e) {
                    negCount += 1;
                    if (mSummary == true)
                        buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                                STATUS_FAILURE);
                    logger.warn("UnpublishExpiredJob: " + CMS.getLogMessage("JOBS_FIND_REQUEST_ERROR",
                                    cert.getSerialNumber().toString(16) + e.getMessage()), e);
                }
                try {
                    if ((mPublisherProcessor != null) &&
                            mPublisherProcessor.isCertPublishingEnabled()) {
                        mPublisherProcessor.unpublishCert(cert, req);
                        if (mSummary == true)
                            buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                                    STATUS_SUCCESS);
                        count += 1;
                    } else {
                        negCount += 1;
                    }
                } catch (Exception e) {
                    negCount += 1;
                    if (mSummary == true)
                        buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                                STATUS_FAILURE);
                    logger.warn("UnpublishExpiredJob: " + CMS.getLogMessage("JOBS_UNPUBLISH_ERROR",
                                    cert.getSerialNumber().toString(16) + e.getMessage()), e);
                }
            } // ridString != null
            else {
                try {
                    if ((mPublisherProcessor != null) &&
                            mPublisherProcessor.isCertPublishingEnabled()) {
                        mPublisherProcessor.unpublishCert(cert, null);
                        if (mSummary == true)
                            buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                                    STATUS_SUCCESS);
                        count += 1;
                    } else {
                        negCount += 1;
                    }
                } catch (Exception e) {
                    negCount += 1;
                    if (mSummary == true)
                        buildItemParams(IEmailFormProcessor.TOKEN_STATUS,
                                STATUS_FAILURE);
                    logger.warn("UnpublishExpiredJob: " + CMS.getLogMessage("JOBS_UNPUBLISH_ERROR",
                                    cert.getSerialNumber().toString(16) + e.getMessage()), e);
                }
            } // ridString == null

            // inLdapPublishDir flag should have been set by the
            // unpublish() method

            // if summary is enabled, form the item content
            if (mSummary) {
                EmailFormProcessor emailItemFormProcessor = new EmailFormProcessor();
                String c = emailItemFormProcessor.getEmailContent(itemForm,
                        mItemParams);

                // add item content to the item list
                if (itemListContent == null) {
                    itemListContent = c;
                } else {
                    itemListContent += c;
                }
            }
        }

        // time for summary
        if (mSummary == true) {
            buildContentParams(IEmailFormProcessor.TOKEN_ID,
                    mId);
            buildContentParams(IEmailFormProcessor.TOKEN_SUMMARY_ITEM_LIST,
                    itemListContent);
            buildContentParams(IEmailFormProcessor.TOKEN_SUMMARY_TOTAL_NUM,
                    String.valueOf(count + negCount));
            buildContentParams(IEmailFormProcessor.TOKEN_SUMMARY_SUCCESS_NUM,
                    String.valueOf(count));
            buildContentParams(IEmailFormProcessor.TOKEN_SUMMARY_FAILURE_NUM,
                    String.valueOf(negCount));
            buildContentParams(IEmailFormProcessor.TOKEN_EXECUTION_TIME,
                    nowString);

            EmailFormProcessor emailFormProcessor = new EmailFormProcessor();
            String mailContent =
                    emailFormProcessor.getEmailContent(contentForm,
                            mContentParams);

            mailSummary(mailContent);
        }
    }

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     *
     * @return String array of configuration parameter names.
     */
    @Override
    public String[] getConfigParams() {
        return (mConfigParams);
    }
}
