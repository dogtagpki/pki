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

import java.io.IOException;
import java.util.Hashtable;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.notification.ENotificationException;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.cms.notification.MailNotification;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.jobs.JobConfig;
import com.netscape.cmscore.jobs.JobCron;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.notification.EmailTemplate;
import com.netscape.cmscore.request.Request;

/**
 * This abstract class is a base job for real job extensions for the
 * Jobs Scheduler.
 *
 * @version $Revision$, $Date$
 */
public abstract class Job implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Job.class);

    // config parameters...
    protected static final String PROP_SUMMARY = "summary";
    protected static final String PROP_ENABLED = "enabled";
    protected static final String PROP_EMAIL_SUBJECT = "emailSubject";
    protected static final String PROP_EMAIL_TEMPLATE = "emailTemplate";
    protected static final String PROP_ITEM_TEMPLATE = "itemTemplate";
    protected static final String PROP_SENDER_EMAIL = "senderEmail";
    protected static final String PROP_RECEIVER_EMAIL = "recipientEmail";

    protected static final String STATUS_FAILURE = "failed";
    protected static final String STATUS_SUCCESS = "succeeded";

    protected CMSEngine engine;

    // variables used by the Job Scheduler Daemon
    protected String mImplName = null;
    protected JobConfig mConfig;
    protected String mId = null;
    protected String mCron = null;
    protected JobCron mJobCron;

    protected static String[] mConfigParams = null;

    protected String mSummaryMailSubject = null;
    protected boolean mMailHTML = false;
    protected String mMailForm = null;
    protected String mItemForm = null;
    protected String mSummarySenderEmail = null;
    protected String mSummaryReceiverEmail = null;
    protected Hashtable<String, Object> mContentParams = new Hashtable<>();
    protected Hashtable<String, Object> mItemParams = new Hashtable<>();

    boolean stopped;

    public Job() {
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     *
     * @return String array of configuration parameter names.
     */
    public abstract String[] getConfigParams();

    /**
     * tells if the job is enabled
     *
     * @return a boolean value indicating whether the job is enabled
     *         or not
     */
    public boolean isEnabled() {
        boolean enabled = false;

        try {
            enabled = mConfig.isEnabled();
        } catch (EBaseException e) {
        }
        return enabled;
    }

    /**
     * Initialize from the configuration file.
     *
     * @param id String name of this instance
     * @param implName string name of this implementation
     * @param config configuration store for this instance
     * @exception EBaseException any initialization failure
     */
    public void init(JobsScheduler scheduler, String id, String implName, JobConfig config) throws EBaseException {

        logger.info("Job: Initializing job " + id);

        mId = id;

        mImplName = implName;
        logger.info("Job: - plugin: " + implName);

        mConfig = config;

        mCron = config.getCron();
        logger.info("Job: - cron: " + mCron);

        if (mCron != null) {
            mJobCron = scheduler.createJobCron(mCron);
        }
    }

    @Override
    public abstract void run();

    /***********************
     * public methods
     ***********************/

    /**
     * get instance id.
     *
     * @return a String identifier
     */
    public String getId() {
        return mId;
    }

    /**
     * set instance id.
     *
     * @param id String id of the instance
     */
    public void setId(String id) {
        mId = id;
    }

    /**
     * get cron string associated with this job
     *
     * @return a JobCron object that represents the schedule of this job
     */
    public JobCron getJobCron() {
        return mJobCron;
    }

    /**
     * gets the plugin name of this job.
     *
     * @return a String that is the name of this implementation
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * Gets the configuration substore used by this job
     *
     * @return configuration store
     */
    public JobConfig getConfigStore() {
        return mConfig;
    }

    /*
     * get form file content from disk
     */
    protected String getTemplateContent(String templatePath) {
        String templateString = null;

        /*
         * get template file from disk
         */
        EmailTemplate template = new EmailTemplate(templatePath);

        if (!template.init()) {
            logger.warn("Job: " + CMS.getLogMessage("JOBS_TEMPLATE_INIT_ERROR"));
            return null;
        }

        // this should take care of inner tempaltes not being html
        // we go with the outter template
        if (template.isHTML()) {
            mMailHTML = true;
        }
        templateString = template.toString();

        return templateString;
    }

    protected void mailSummary(String content) {

        logger.info("Job: Sending email to " + mSummaryReceiverEmail);

        // no need for email resolver here...
        MailNotification mn = engine.getMailNotification();

        mn.setFrom(mSummarySenderEmail);
        mn.setTo(mSummaryReceiverEmail);
        mn.setSubject(mSummaryMailSubject);
        if (mMailHTML == true) {
            mn.setContentType("text/html");
        }

        mn.setContent(content);
        try {
            mn.sendNotification();
        } catch (ENotificationException e) {
            logger.warn("Job: " + CMS.getLogMessage("JOBS_SEND_NOTIFICATION", e.toString()), e);
        } catch (IOException e) {
            logger.warn("Job: " + CMS.getLogMessage("JOBS_SEND_NOTIFICATION", e.toString()), e);
        }
    }

    protected void buildItemParams(X509CertImpl cert) {
        mItemParams.put(IEmailFormProcessor.TOKEN_SERIAL_NUM,
                cert.getSerialNumber().toString());
        mItemParams.put(IEmailFormProcessor.TOKEN_HEX_SERIAL_NUM,
                cert.getSerialNumber().toString(16));
        mItemParams.put(IEmailFormProcessor.TOKEN_ISSUER_DN,
                cert.getIssuerName().toString());
        mItemParams.put(IEmailFormProcessor.TOKEN_SUBJECT_DN,
                cert.getSubjectName().toString());
        mItemParams.put(IEmailFormProcessor.TOKEN_NOT_AFTER,
                cert.getNotAfter().toString());
        mItemParams.put(IEmailFormProcessor.TOKEN_NOT_BEFORE,
                cert.getNotBefore().toString());
        // ... and more
    }

    protected void buildItemParams(Request r) {
        String re = r.getExtDataInString(Request.HTTP_PARAMS, "csrRequestorEmail");

        if (re != null) {
            mItemParams.put(IEmailFormProcessor.TOKEN_REQUESTOR_EMAIL, re);
        }

        String ct = r.getExtDataInString(Request.HTTP_PARAMS, Request.CERT_TYPE);

        if (ct != null) {
            mItemParams.put(IEmailFormProcessor.TOKEN_CERT_TYPE, ct);
        }

        String rt = r.getExtDataInString(Request.REQ_TYPE);

        if (rt != null) {
            mItemParams.put(IEmailFormProcessor.TOKEN_REQUEST_TYPE, rt);
        }
    }

    protected void buildItemParams(String name, String val) {
        if (val != null)
            mItemParams.put(name, val);
        else {
            logger.debug("Job: buildItemParams: null value for name= " + name);
            mItemParams.put(name, "");
        }
    }

    protected void buildContentParams(String name, String val) {
        if (val != null)
            mContentParams.put(name, val);
        else {
            logger.debug("Job: buildContentParams: null value for name= " + name);
            mContentParams.put(name, "");
        }
    }

    /**
     * Request the job to stop gracefully. The job may not stop immediately.
     */
    public void stop() {
        stopped = true;
    }

    /**
     * Check whether the job has been asked to stop. Long running jobs should call
     * this method occasionally inside the run() method and exit gracefully if it
     * returns true.
     */
    public boolean isStopped() {
        return stopped;
    }
}
