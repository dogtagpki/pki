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
package com.netscape.cmscore.jobs;

import java.util.Calendar;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.jobs.EJobsException;
import com.netscape.certsrv.jobs.IJob;
import com.netscape.certsrv.jobs.IJobCron;
import com.netscape.certsrv.jobs.JobPlugin;
import com.netscape.cmscore.apps.CMS;

/**
 * This is a daemon thread that handles scheduled jobs like cron would
 * do with different jobs. This daemon wakes up at a pre-configured
 * interval to see
 * if there is any job to be done, if so, a thread is created to execute
 * the job(s).
 * <p>
 * The interval <b>jobsScheduler.interval</b> in the configuration is specified as number of minutes. If not set, the
 * default is 1 minute. Note that the cron specification for each job CAN NOT be finer than the granularity of the
 * Scheduler daemon interval. For example, if the daemon interval is set to 5 minute, a job cron for every minute at 7am
 * on each Tuesday (e.g. * 7 * * 2) will result in the execution of the job thread only once every 5 minutes during that
 * hour. <b>The inteval value is recommended at 1 minute, setting it otherwise has the potential of forever missing the
 * beat</b>. Use with caution.
 *
 * @author cfu
 * @see JobCron
 * @version $Revision$, $Date$
 */
public class JobsScheduler implements Runnable, ISubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JobsScheduler.class);

    /**
     * The ID of this component
     */
    public final static String ID = "jobsScheduler";

    /**
     * constant that represents the configuration parameter
     * "enabled" for this component in CMS.cfg. The value of which
     * tells CMS whether the JobsScheduler is enabled or not
     */
    public static final String PROP_ENABLED = "enabled";

    /**
     * constant that represents the configuration parameter
     * "interval" for this component in CMS.cfg. The value of which
     * tells CMS the interval that the JobsScheduler thread should
     * wake up and look for jobs to execute
     */
    public static final String PROP_INTERVAL = "interval";

    /**
     * constant that represents the configuration parameter
     * "class" for this component in CMS.cfg. The values of which are
     * the actual implementation classes
     */
    public static final String PROP_CLASS = "class";

    /**
     * constant that represents the configuration parameter
     * "job" for this component in CMS.cfg. The values of which gives
     * configuration information specific to one single job instance.
     * There may be multiple jobs served by the jobsScheduler
     */
    public static final String PROP_JOB = "job";

    /**
     * constant that represents the configuration parameter
     * "impl" for this component in CMS.cfg. The values of which are
     * actual plugin implementation(s)
     */
    public static final String PROP_IMPL = "impl";

    /**
     * constant that represents the configuration parameter
     * "pluginName" for this component in CMS.cfg. The value of which
     * gives the pluginName for the job it associates with
     */
    public static final String PROP_PLUGIN = "pluginName";

    protected static final long MINUTE_MILLI = 60000;
    protected static final String DELIM = ",";

    /**
     * Scheduler thread doing job scheduling
     */
    protected String mId = ID;
    protected Thread mScheduleThread = null;

    public Hashtable<String, JobPlugin> mJobPlugins = new Hashtable<String, JobPlugin>();
    public Hashtable<String, IJob> mJobs = new Hashtable<String, IJob>();
    private Hashtable<String, Thread> mJobThreads = new Hashtable<String, Thread>();

    private IConfigStore mConfig = null;

    // in milliseconds. daemon wakeup interval, default 1 minute.
    private long mInterval = 0;

    // singleton enforcement

    private static JobsScheduler mInstance = new JobsScheduler();

    public static JobsScheduler getInstance() {
        return mInstance;
    }

    // end singleton enforcement.

    private JobsScheduler() {
    }

    /**
     * read from the config file all implementations of Jobs,
     * register and initialize them
     * <p>
     * the config params have the following formats: jobScheduler.impl.[implementation name].class=[package name]
     * jobScheduler.job.[job name].pluginName=[implementation name] jobScheduler.job.[job name].cron=[crontab format]
     * jobScheduler.job.[job name].[any job specific params]=[values]
     * @param config jobsScheduler configStore
     */
    public void init(IConfigStore config)
            throws EBaseException, EJobsException {

        // read in config parameters and set variables
        mConfig = config;

        // getting/setting interval
        int i;

        try {
            i = mConfig.getInteger(PROP_INTERVAL);
        } catch (Exception e) {
            i = 1; // default 1 minute
        }
        setInterval(i);

        IConfigStore c = mConfig.getSubStore(PROP_IMPL);
        Enumeration<String> mImpls = c.getSubStoreNames();

        // register all job plugins
        while (mImpls.hasMoreElements()) {
            String id = mImpls.nextElement();
            String pluginPath = c.getString(id + "." + PROP_CLASS);

            JobPlugin plugin = new JobPlugin(id, pluginPath);

            mJobPlugins.put(id, plugin);
        }

        // register all jobs
        c = config.getSubStore(PROP_JOB);
        Enumeration<String> jobs = c.getSubStoreNames();

        while (jobs.hasMoreElements()) {
            String jobName = jobs.nextElement();
            String implName = c.getString(jobName + "." + PROP_PLUGIN);
            JobPlugin plugin = mJobPlugins.get(implName);

            if (plugin == null) {
                logger.error(CMS.getLogMessage("CMSCORE_JOBS_CLASS_NOT_FOUND", implName));
                throw new EJobsException(CMS.getUserMessage("CMS_JOB_PLUGIN_NOT_FOUND", implName));
            }
            String classPath = plugin.getClassPath();

            // instantiate and init the job
            try {
                IJob job = (IJob)
                        Class.forName(classPath).newInstance();
                IConfigStore jconfig = c.getSubStore(jobName);

                job.init(this, jobName, implName, jconfig);

                // register the job
                mJobs.put(jobName, job);

            } catch (ClassNotFoundException e) {
                logger.error(CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()), e);
                throw new EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", classPath), e);

            } catch (IllegalAccessException e) {
                logger.error(CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()), e);
                throw new EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", classPath), e);

            } catch (InstantiationException e) {
                logger.error(CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()), e);
                throw new EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", classPath), e);

            } catch (EBaseException e) {
                logger.error(CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()), e);
                throw e;
            }
        }

        // are we enabled?
        if (mConfig.getBoolean(PROP_ENABLED, false) == true) {
            // start the daemon thread
            startDaemon();
        }
    }

    /**
     * Retrieves all the job implementations.
     *
     * @return a Hashtable of available job plugin implementations
     */
    public Hashtable<String, JobPlugin> getPlugins() {
        return mJobPlugins;
    }

    /**
     * Retrieves all the job instances.
     *
     * @return a Hashtable of job instances
     */
    public Hashtable<String, IJob> getInstances() {
        return mJobs;
    }

    /**
     * when wake up:
     * . execute the scheduled job(s)
     * * if job still running from previous interval, skip it
     * . figure out when is the next wakeup time (every interval). If
     * current wakup time runs over the interval, skip the missed interval(s)
     * . sleep till the next wakeup time
     */
    public void run() {
        long wokeupTime = 0;

        while (true) {
            // get time now
            Calendar cal = Calendar.getInstance();
            long rightNow = cal.getTime().getTime();
            long duration;
            long second = cal.get(Calendar.SECOND);

            if (second != 1) { // scheduler needs adjustment
                // adjust to wake up at 1st second
                long milliSec = cal.get(Calendar.MILLISECOND);

                // possible to be at exactly second 1, millisecond 0,
                // just let it skip to next second, fine.
                duration = (60 - second) * 1000 + 1000 - milliSec;
                logger.info("JobsScheduler: adjustment for cron behavior: sleep for " + duration + " milliseconds");
            } else {

                // when is the next wakeup time for the JobsScheduler?
                // reset next wakeup time - wake up every preset interval

                duration = mInterval - rightNow + wokeupTime;

            }

            while (duration < 0) {
                duration += mInterval;
            }

            if (duration != 0) {
                try {
                    Thread.sleep(duration);
                } catch (InterruptedException e) {
                    System.out.println(e);
                }
            }

            // if (duration == 0), it's time

            // woke up...
            try {
                if (mConfig.getBoolean(PROP_ENABLED, false) == false) {
                    return;
                }
            } catch (Exception e) {
                return;
            }

            // check to see if new jobs are registered
            // ... later

            // get time now
            cal = Calendar.getInstance();

            /**
             * Get the current time outside the jobs while loop
             * to make sure that the rightful jobs are run
             * -- milliseconds from the epoch
             */
            wokeupTime = cal.getTime().getTime();

            for (Enumeration<IJob> e = mJobs.elements(); e.hasMoreElements(); ) {
                IJob job = e.nextElement();

                // is it enabled?
                IConfigStore cs = job.getConfigStore();

                try {
                    if (cs.getBoolean(PROP_ENABLED, false) == false)
                        continue;
                } catch (Exception ex) {
                    continue; // ignore this job
                }

                // first, check to see if thread already running
                // ...

                // start the job thread if necessary
                if (isShowTime(job, cal) == true) {
                    //	logger.info("JobsScheduler: show time for: "+job.getId());

                    // if previous thread still alive, skip
                    Thread jthread = mJobThreads.get(job.getId());

                    if ((jthread == null) || (!jthread.isAlive())) {
                        Thread jobThread = new Thread((Runnable) job, job.getId());

                        jobThread.start();
                        // put into job thread control
                        mJobThreads.put(job.getId(), jobThread);
                    } else {
                        // previous thread still alive, log it
                        logger.info("JobsScheduler: Job " + job.getId() + " still running...skipping this round");
                    }
                }
            } // for

        }
    }

    /**
     * Creates a job cron. Each job is associated with a "cron" which
     * specifies the rule of frequency that this job should be
     * executed (e.g. every Sunday at midnight). This method is
     * called by each job at initialization time.
     *
     * @param cs the string that represents the cron. See IJobCron
     *            for detail of the format.
     * @return IJobCron an IJobCron
     * @exception EBaseException when the cron string, cs, can not be
     *                parsed correctly
     */
    public IJobCron createJobCron(String cs) throws EBaseException {
        return new JobCron(cs);
    }

    /**
     * Is it time for the job?
     */
    protected boolean isShowTime(IJob job, Calendar now) {
        JobCron jcron = (JobCron) job.getJobCron();

        logger.info("JobsScheduler: jobcron: " + jcron);
        if (jcron == null) {
            // the impossible has happened
            return false;
        }

        /**
         * is it the right month?
         */
        Vector<CronRange> moy =
                jcron.getItem(JobCron.CRON_MONTH_OF_YEAR).getElements();

        int cronMoy = jcron.MOY_cal2cron(now);

        if (jcron.isElement(cronMoy, moy) == false) {
            return false;
        }
        // is the right month!

        /**
         * is it the right date?
         */
        Vector<CronRange> dow = jcron.getItem(JobCron.CRON_DAY_OF_WEEK).getElements();
        Vector<CronRange> dom = jcron.getItem(JobCron.CRON_DAY_OF_MONTH).getElements();

        // can't be both empty
        if ((dow.isEmpty()) && dom.isEmpty()) {
            // throw... or return false?
        }

        int cronDow = jcron.DOW_cal2cron(now);

        if ((jcron.isElement(cronDow, dow) == false) &&
                (jcron.isElement(now.get(Calendar.DAY_OF_MONTH), dom) == false)) {
            return false;
        }
        // is the right date!

        /**
         * is it the right hour?
         */
        Vector<CronRange> hour = jcron.getItem(JobCron.CRON_HOUR).getElements();

        if (jcron.isElement(now.get(Calendar.HOUR_OF_DAY), hour) == false) {
            return false;
        }
        // is the right hour!

        /**
         * is it the right minute?
         */
        Vector<CronRange> minute = jcron.getItem(JobCron.CRON_MINUTE).getElements();

        if (jcron.isElement(now.get(Calendar.MINUTE), minute) == false) {
            return false;
        }
        // is the right minute!  We're on!

        return true;
    }

    /**
     * Retrieves id (name) of this subsystem.
     *
     * @return name of the Jobs Scheduler subsystem
     */
    public String getId() {
        return mId;
    }

    /**
     * Sets id string to this subsystem.
     * <p>
     * Use with caution. Should not do it when sharing with others
     *
     * @param id name to be applied to an Jobs Scheduler subsystem
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * Starts up the JobsScheduler daemon. Usually called from the
     * initialization method when it's successfully initialized.
     */
    public void startDaemon() {
        mScheduleThread = new Thread(this, "JobScheduler");
        logger.info("JobsScheduler: started Jobs Scheduler daemon thread");
        mScheduleThread.setDaemon(true);
        mScheduleThread.start();
    }

    /**
     * registers the administration servlet with the administration subsystem.
     */
    public void startup() throws EBaseException {
        //remove, already logged from S_ADMIN
        //String infoMsg = "JobsScheduler: subsystem administration Servlet registered";
        //logger.info(infoMsg);
    }

    /**
     * shuts down Jobs one by one.
     * <P>
     */
    public void shutdown() {
        for (IJob job : mJobs.values()) {
            job.stop();
        }
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves the configuration parameters of the given
     * implementation. It is used to return to the Console for
     * configuration
     *
     * @param implName the pulubin implementation name
     * @return a String array of required configuration parameters of
     *         the given implementation.
     * @exception EJobsException when job plugin implementation can
     *                not be found, instantiation is impossible, permission problem
     *                with the class.
     */
    public String[] getConfigParams(String implName)
            throws EJobsException {
        logger.trace("JobsScheduler: in getCofigParams()");

        // is this a registered implname?
        JobPlugin plugin = mJobPlugins.get(implName);

        if (plugin == null) {
            logger.error(CMS.getLogMessage("CMSCORE_JOBS_CLASS_NOT_FOUND", implName));
            logger.error("JobsScheduler: Job plugin " + implName + " not found.");
            throw new EJobsException(CMS.getUserMessage("CMS_JOB_PLUGIN_NOT_FOUND",
                    implName));
        }

        // XXX can find an instance of this plugin in existing
        // auth manager instantces to avoid instantiation just for this.

        // a temporary instance
        String className = plugin.getClassPath();

        logger.trace("JobsScheduler: className = " + className);
        try {
            IJob jobInst = (IJob)
                    Class.forName(className).newInstance();
            logger.trace("JobsScheduler: class instantiated");
            return (jobInst.getConfigParams());

        } catch (InstantiationException e) {
            logger.error(CMS.getLogMessage("CMSCORE_JOBS_CREATE_NEW", e.toString()));
            logger.error("JobsScheduler: class NOT instantiated: " + e.getMessage(), e);
            throw new EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", className));

        } catch (ClassNotFoundException e) {
            logger.error(CMS.getLogMessage("CMSCORE_JOBS_CREATE_NEW", e.toString()));
            logger.error("JobsScheduler: class NOT instantiated: " + e.getMessage(), e);
            throw new EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", className));

        } catch (IllegalAccessException e) {
            logger.error(CMS.getLogMessage("CMSCORE_JOBS_CREATE_NEW", e.toString()));
            logger.error("JobsScheduler: class NOT instantiated: " + e.getMessage(), e);
            throw new EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", className));
        }
    }

    /**
     * Sets daemon's wakeup interval.
     *
     * @param minutes time in minutes that is to be the frequency of
     *            JobsScheduler wakeup call.
     */
    public void setInterval(int minutes) {
        mInterval = minutes * MINUTE_MILLI;
    }

    /**
     * Writes a message to the system log.
     *
     * @param level an integer representing the log message level.
     *            Depending on the configuration set by the administrator, this
     *            value is a determining factor for whether this message will be
     *            actually logged or not. The lower the level, the higher the
     *            priority, and the higher chance it will be logged.
     * @param msg the message to be written. Ideally should call
     *            CMS.getLogMessage() to get the localizable message
     *            from the log properties file.
     */
    public void log(int level, String msg) {
    }

    public Hashtable<String, JobPlugin> getJobPlugins() {
        return mJobPlugins;
    }
}
