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
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.jobs.IJob;
import com.netscape.certsrv.jobs.IJobCron;
import com.netscape.certsrv.jobs.IJobsScheduler;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;

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
 * @see com.netscape.certsrv.jobs.IJob
 * @see com.netscape.cms.jobs.AJobBase
 */
public class RequestInQueueJob extends AJobBase
        implements IJob, Runnable, IExtendedPluginInfo {
    protected static final String PROP_SUBSYSTEM_ID = "subsystemId";

    IAuthority mSub = null;
    IRequestQueue mReqQ = null;
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
    public String[] getExtendedPluginInfo(Locale locale) {
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
    public void init(ISubsystem owner, String id, String implName, IConfigStore config) throws
            EBaseException {
        mConfig = config;
        mId = id;
        mImplName = implName;

        // read from the configuration file
        String sub = mConfig.getString(PROP_SUBSYSTEM_ID);

        mSub = (IAuthority)
                CMS.getSubsystem(sub);
        if (mSub == null) {
            // take this as disable
            mSummary = false;
            return;
        }

        mReqQ = mSub.getRequestQueue();

        mCron = mConfig.getString(IJobCron.PROP_CRON);
        if (mCron == null) {
            return;
        }

        // parse cron string into a JobCron class
        IJobsScheduler scheduler = (IJobsScheduler) owner;

        mJobCron = scheduler.createJobCron(mCron);

        // initialize the summary related config info
        IConfigStore sc = mConfig.getSubStore(PROP_SUMMARY);

        if (sc.getBoolean(PROP_ENABLED, false)) {
            mSummary = true;
            mSummaryMailSubject = sc.getString(PROP_EMAIL_SUBJECT);
            mMailForm = sc.getString(PROP_EMAIL_TEMPLATE);
            //		mItemForm = sc.getString(PROP_ITEM_TEMPLATE);
            mSummarySenderEmail = sc.getString(PROP_SENDER_EMAIL);
            mSummaryReceiverEmail = sc.getString(PROP_RECEIVER_EMAIL);
        } else {
            mSummary = false;
        }
    }

    /**
     * summarize the queue status and mail it
     */
    public void run() {
        if (mSummary == false)
            return;

        Date date = CMS.getCurrentDate();
        DateFormat dateFormat = DateFormat.getDateTimeInstance();
        String nowString = dateFormat.format(date);

        int count = 0;
        IRequestList list =
                mReqQ.listRequestsByStatus(RequestStatus.PENDING);

        while (list != null && list.hasMoreElements()) {
            list.nextRequestId();

            /*  This is way too slow
             // get request from request id
             IRequest req = null;
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

        buildContentParams(IEmailFormProcessor.TOKEN_ID, mId);
        buildContentParams(IEmailFormProcessor.TOKEN_SUMMARY_TOTAL_NUM,
                String.valueOf(count));
        buildContentParams(IEmailFormProcessor.TOKEN_EXECUTION_TIME,
                nowString);

        IEmailFormProcessor emailFormProcessor = CMS.getEmailFormProcessor();
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
    public String[] getConfigParams() {
        return mConfigParams;
    }
}
