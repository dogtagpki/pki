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
import java.util.Collection;
import java.util.Date;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.jobs.JobConfig;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.notification.EmailFormProcessor;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRecord;

/**
 * A job for the Jobs Scheduler. This job checks in the internal ldap
 * db for requests currently in the request queue and send a summary
 * report to the administrator
 * <p>
 * the $TOKENS that are available for the this jobs's summary outer form are:<br>
 * <UL>
 * $InstanceID $SummaryTotalNum $ExecutionTime
 * </UL>
 *
 * @version $Revision$, $Date$
 * @see com.netscape.cms.jobs.Job
 */
public class RequestInQueueJob extends Job
        implements IExtendedPluginInfo {
    protected static final String PROP_SUBSYSTEM_ID = "subsystemId";

    IAuthority mSub = null;
    RequestQueue mReqQ;
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
                    "subsystemId",
                    "summary.enabled",
                    "summary.emailSubject",
                    "summary.emailTemplate",
                    "summary.senderEmail",
                    "summary.recipientEmail"
        };

    /**
     * holds help text for this plugin
     */
    @Override
    public String[] getExtendedPluginInfo() {
        String s[] = {
                IExtendedPluginInfo.HELP_TEXT +
                        "; A job that checks for enrollment requests in the " +
                        "queue, and reports to recipientEmail",
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
                "subsystemId;choice(ca,ra);The type of subsystem this job is " +
                        "for",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-jobrules-requestinqueuejob",
            };

        return s;
    }

    /**
     * initialize from the configuration file
     *
     * @param id String name of this instance
     * @param implName string name of this implementation
     * @param config configuration store for this instance
     * @exception EBaseException
     */
    @Override
    public void init(JobsScheduler scheduler, String id, String implName, JobConfig config) throws
            EBaseException {

        super.init(scheduler, id, implName, config);

        // read from the configuration file
        String sub = mConfig.getString(PROP_SUBSYSTEM_ID);

        mSub = (IAuthority) engine.getSubsystem(sub);
        if (mSub == null) {
            // take this as disable
            mSummary = false;
            return;
        }

        mReqQ = engine.getRequestQueue();

        // initialize the summary related config info
        ConfigStore sc = mConfig.getSubStore(PROP_SUMMARY, ConfigStore.class);
        boolean enabled = sc.getBoolean(PROP_ENABLED, false);
        logger.info("RequestInQueueJob: - enabled: " + enabled);

        if (enabled) {
            mSummary = true;

            mSummaryMailSubject = sc.getString(PROP_EMAIL_SUBJECT);
            logger.info("RequestInQueueJob: - subject: " + mSummaryMailSubject);

            mMailForm = sc.getString(PROP_EMAIL_TEMPLATE);
            logger.info("RequestInQueueJob: - mail template: " + mMailForm);

            // mItemForm = sc.getString(PROP_ITEM_TEMPLATE);
            // logger.info("RequestInQueueJob: - item template: " + mItemForm);

            mSummarySenderEmail = sc.getString(PROP_SENDER_EMAIL);
            logger.info("RequestInQueueJob: - sender email: " + mSummarySenderEmail);

            mSummaryReceiverEmail = sc.getString(PROP_RECEIVER_EMAIL);
            logger.info("RequestInQueueJob: - receiver email: " + mSummaryReceiverEmail);

        } else {
            mSummary = false;
        }
    }

    /**
     * summarize the queue status and mail it
     */
    @Override
    public void run() {
        try {
            runImpl();
        } catch (Exception e) {
            logger.error("RequestInQueue: " + e.getMessage(), e);
        }
    }

    public void runImpl() throws Exception {

        logger.info("RequestInQueueJob: Running job " + mId);

        if (mSummary == false)
            return;

        Date date = new Date();
        DateFormat dateFormat = DateFormat.getDateTimeInstance();
        String nowString = dateFormat.format(date);

        logger.info("RequestInQueueJob: Searching for pending requests");
        int count = 0;
        Collection<RequestRecord> records = mReqQ.listRequestsByStatus(RequestStatus.PENDING);

        for (RequestRecord record : records) {
            RequestId requestID = record.getRequestId();
            logger.info("RequestInQueueJob: - " + requestID.toHexString());

            /*  This is way too slow
             // get request from request id
             Request req = null;
             try {
             req = mReqQ.findRequest(rid);
             } catch (EBaseException e) {
             System.out.println(e.toString());
             }
             */
            count++;
        }

        //		if (count == 0) return;

        String contentForm = null;

        contentForm = getTemplateContent(mMailForm);

        buildContentParams(EmailFormProcessor.TOKEN_ID, mId);
        buildContentParams(EmailFormProcessor.TOKEN_SUMMARY_TOTAL_NUM, String.valueOf(count));
        buildContentParams(EmailFormProcessor.TOKEN_EXECUTION_TIME, nowString);

        EmailFormProcessor emailFormProcessor = new EmailFormProcessor();
        String mailContent =
                emailFormProcessor.getEmailContent(contentForm,
                        mContentParams);

        mailSummary(mailContent);
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
