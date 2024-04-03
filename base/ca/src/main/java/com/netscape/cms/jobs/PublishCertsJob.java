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

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSearchResults;
import com.netscape.cmscore.jobs.JobConfig;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.notification.EmailFormProcessor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;

/**
 * a job for the Jobs Scheduler. This job checks in the internal ldap
 * db for valid certs that have not been published to the
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
public class PublishCertsJob extends Job
        implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PublishCertsJob.class);

    RequestRepository requestRepository;
    RequestQueue mReqQ;
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
    public String[] getExtendedPluginInfo() {
        String s[] = {
                IExtendedPluginInfo.HELP_TEXT +
                        "; A job that checks for valid certificates in the " +
                        "database, that have not been published and publish them to " +
                        "the publishing directory",
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
    public void init(JobsScheduler scheduler, String id, String implName, JobConfig config) throws EBaseException {

        super.init(scheduler, id, implName, config);

        CAEngine caEngine = (CAEngine) engine;
        requestRepository = caEngine.getRequestRepository();
        mReqQ = caEngine.getRequestQueue();
        mRepository = caEngine.getCertificateRepository();
        mPublisherProcessor = caEngine.getPublisherProcessor();

        // initialize the summary related config info
        ConfigStore sc = mConfig.getSubStore(PROP_SUMMARY, ConfigStore.class);
        boolean enabled = sc.getBoolean(PROP_ENABLED, false);
        logger.info("PublishCertsJob: - enabled: " + enabled);

        if (enabled) {
            mSummary = true;

            mSummaryMailSubject = sc.getString(PROP_EMAIL_SUBJECT);
            logger.info("PublishCertsJob: - subject: " + mSummaryMailSubject);

            mMailForm = sc.getString(PROP_EMAIL_TEMPLATE);
            logger.info("PublishCertsJob: - mail template: " + mMailForm);

            mItemForm = sc.getString(PROP_ITEM_TEMPLATE);
            logger.info("PublishCertsJob: - item template: " + mItemForm);

            mSummarySenderEmail = sc.getString(PROP_SENDER_EMAIL);
            logger.info("PublishCertsJob: - sender email: " + mSummarySenderEmail);

            mSummaryReceiverEmail = sc.getString(PROP_RECEIVER_EMAIL);
            logger.info("PublishCertsJob: - receiver email: " + mSummaryReceiverEmail);

        } else {
            mSummary = false;
        }
    }

    /**
     * look in the internal db for certificateRecords that are
     * valid but not published
     * The publish() method should set <b>InLdapPublishDir</b> flag accordingly.
     * if publish unsuccessfully, log it -- unsuccessful certs should be
     * picked up and attempted again at the next scheduled run
     */
    @Override
    public void run() {

        logger.info("PublishCertsJob: Running job " + mId);

        // get time now..."now" is before the loop
        Date date = new Date();
        DateFormat dateFormat = DateFormat.getDateTimeInstance();
        String nowString = dateFormat.format(date);

        // form filter
        String filter = // might need to use "metaInfo"
                "(!(certMetainfo=" + CertRecord.META_LDAPPUBLISH +
                        ":true))";

        DBSearchResults unpublishedCerts = null;

        try {
            unpublishedCerts = mRepository.findCertRecs(filter);
            // bug 399150
            /*
             CertRecordList list = null;
             list = mRepository.findCertRecordsInList(filter,  null, "serialno", 5);
             int size = list.getSize();
             expired = list.getCertRecords(0, size - 1);
             */
        } catch (EBaseException e) {
            logger.warn("PublishCertsJob: " + CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
        }

        int count = 0; // how many have been published successfully
        int negCount = 0; // how many have NOT been published successfully
        String contentForm = null;
        String itemForm = null;
        String itemListContent = null;

        if (mSummary) {
            contentForm = getTemplateContent(mMailForm);
            itemForm = getTemplateContent(mItemForm);
        }

        // filter out the invalid ones and publish them
        // publish() will set inLdapPublishDir flag
        while (unpublishedCerts != null && unpublishedCerts.hasMoreElements()) {
            CertRecord rec = (CertRecord) unpublishedCerts.nextElement();
            if (rec == null)
                break;

            CertId certID = new CertId(rec.getSerialNumber());
            logger.info("PublishCertsJob: Publishing cert " + certID.toHexString());

            X509CertImpl cert = rec.getCertificate();
            Date notAfter = cert.getNotAfter();

            // skip CA certs
            if (cert.getBasicConstraintsIsCA()) {
                logger.info("PublishCertsJob: Cert " + certID.toHexString() + " is a CA cert");
                continue;
            }

            // skip the expired certs
            if (notAfter.before(date)) {
                logger.info("PublishCertsJob: Cert " + certID.toHexString() + " has expired");
                continue;
            }

            if (mSummary)
                buildItemParams(cert);

            // get request id from cert record MetaInfo
            MetaInfo minfo = null;

            try {
                minfo = (MetaInfo) rec.get(CertRecord.ATTR_META_INFO);
            } catch (EBaseException e) {
                negCount += 1;
                if (mSummary)
                    buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_FAILURE);
                logger.warn("PublishCertsJob: " + CMS.getLogMessage("JOBS_META_INFO_ERROR",
                                cert.getSerialNumber().toString(16) + e.getMessage()), e);
            }

            String ridString = null;

            try {
                if (minfo != null)
                    ridString = (String) minfo.get(CertRecord.META_REQUEST_ID);
            } catch (EBaseException e) {
                negCount += 1;
                if (mSummary == true)
                    buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_FAILURE);
                logger.warn("PublishCertsJob: " + CMS.getLogMessage("JOBS_META_REQUEST_ERROR",
                                cert.getSerialNumber().toString(16) + e.getMessage()), e);
            } catch (NullPointerException e) {
                // no requestId in MetaInfo...skip to next record
                negCount += 1;
                if (mSummary == true)
                    buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_FAILURE);
                logger.warn("PublishCertsJob: " + CMS.getLogMessage("JOBS_META_REQUEST_ERROR",
                                cert.getSerialNumber().toString(16) + e.getMessage()), e);
            }

            boolean publishingEnabled =
                    mPublisherProcessor != null &&
                    mPublisherProcessor.isCertPublishingEnabled();
            logger.info("PublishCertsJob: Publishing enabled: " + publishingEnabled);

            if (ridString != null) {
                RequestId rid = new RequestId(ridString);
                logger.info("PublishCertsJob: Request: " + rid.toHexString());

                // get request from request id
                Request req = null;

                try {
                    req = requestRepository.readRequest(rid);
                    if (req != null) {
                        if (mSummary == true)
                            buildItemParams(req);
                    }
                } catch (EBaseException e) {
                    negCount += 1;
                    if (mSummary == true)
                        buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_FAILURE);
                    logger.warn("PublishCertsJob: " + CMS.getLogMessage("JOBS_FIND_REQUEST_ERROR",
                                    cert.getSerialNumber().toString(16) + e.getMessage()), e);
                }

                try {
                    if (publishingEnabled) {

                        logger.info("PublishCertsJob: Publishing cert " + certID.toHexString() + " with request " + rid.toHexString());
                        mPublisherProcessor.publishCert(cert, req);

                        if (mSummary == true)
                            buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_SUCCESS);
                        count += 1;
                    } else {
                        negCount += 1;
                    }
                } catch (Exception e) {
                    negCount += 1;
                    if (mSummary == true)
                        buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_FAILURE);
                    logger.warn("PublishCertsJob: " + CMS.getLogMessage("JOBS_PUBLISH_ERROR",
                                    cert.getSerialNumber().toString(16) + e.getMessage()), e);
                }
            } // ridString != null
            else {
                try {
                    if (publishingEnabled) {

                        logger.info("PublishCertsJob: Publishing cert " + certID.toHexString() + " without request");
                        mPublisherProcessor.publishCert(cert, null);

                        if (mSummary == true)
                            buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_SUCCESS);
                        count += 1;
                    } else {
                        negCount += 1;
                    }
                } catch (Exception e) {
                    negCount += 1;

                    if (mSummary == true)
                        buildItemParams(EmailFormProcessor.TOKEN_STATUS, STATUS_FAILURE);

                    logger.warn("PublishCertsJob: " + CMS.getLogMessage("JOBS_PUBLISH_ERROR",
                                    cert.getSerialNumber().toString(16) + e.getMessage()), e);
                }
            } // ridString == null

            // inLdapPublishDir flag should have been set by the
            // publish() method

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
            buildContentParams(EmailFormProcessor.TOKEN_ID, mId);
            buildContentParams(EmailFormProcessor.TOKEN_SUMMARY_ITEM_LIST, itemListContent);
            buildContentParams(EmailFormProcessor.TOKEN_SUMMARY_TOTAL_NUM, String.valueOf(count + negCount));
            buildContentParams(EmailFormProcessor.TOKEN_SUMMARY_SUCCESS_NUM, String.valueOf(count));
            buildContentParams(EmailFormProcessor.TOKEN_SUMMARY_FAILURE_NUM, String.valueOf(negCount));
            buildContentParams(EmailFormProcessor.TOKEN_EXECUTION_TIME, nowString);

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
        return mConfigParams;
    }
}
