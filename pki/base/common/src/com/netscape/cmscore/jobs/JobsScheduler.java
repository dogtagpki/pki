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


import java.util.*;
import java.io.*;
import java.lang.*;
import netscape.ldap.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.jobs.*;
import com.netscape.cmscore.util.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.*;
import netscape.security.x509.*;


/**
 * This is a daemon thread that handles scheduled jobs like cron would
 * do with different jobs.  This daemon wakes up at a pre-configured
 * interval to see
 * if there is any job to be done, if so, a thread is created to execute
 * the job(s).
 * <p>
 * The interval <b>jobsScheduler.interval</b> in the configuration is
 * specified as number of minutes.  If not set, the default is 1 minute.
 * Note that the cron specification for each job CAN NOT be finer than
 * the granularity of the Scheduler daemon interval.  For example, if
 * the daemon interval is set to 5 minute, a job cron for every minute
 * at 7am on each Tuesday (e.g. * 7 * * 2) will result in the
 * execution of the job thread only once every 5 minutes during that
 * hour.  <b>The inteval value is recommended at 1 minute, setting it
 * otherwise has the potential of forever missing the beat</b>. Use
 * with caution.
 * 
 * @author cfu
 * @see JobCron
 * @version $Revision$, $Date$
 */
public class JobsScheduler implements Runnable, IJobsScheduler {

    protected static final long MINUTE_MILLI = 60000;
    protected static final String DELIM = ",";

    /**
     * Scheduler thread doing job scheduling
     */
    protected String mId = ID;
    protected Thread mScheduleThread = null;

    public Hashtable mJobPlugins = new Hashtable();
    public Hashtable mJobs = new Hashtable();
    private Hashtable mJobThreads = new Hashtable();

    private IConfigStore mConfig = null;
    private ILogger mLogger = null;

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
     * the config params have the following formats:
     * jobScheduler.impl.[implementation name].class=[package name]
     * jobScheduler.job.[job name].pluginName=[implementation name]
     * jobScheduler.job.[job name].cron=[crontab format]
     * jobScheduler.job.[job name].[any job specific params]=[values]
     * 
     * @param config jobsScheduler configStore
     */
    public void init(ISubsystem owner, IConfigStore config)
        throws EBaseException, EJobsException {
        mLogger = CMS.getLogger();

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
        Enumeration mImpls = c.getSubStoreNames();

        // register all job plugins
        while (mImpls.hasMoreElements()) {
            String id = (String) mImpls.nextElement();
            String pluginPath = c.getString(id + "." + PROP_CLASS);

            JobPlugin plugin = new JobPlugin(id, pluginPath);

            mJobPlugins.put(id, plugin);
        }

        // register all jobs
        c = config.getSubStore(PROP_JOB);
        Enumeration jobs = c.getSubStoreNames();

        while (jobs.hasMoreElements()) {
            String jobName = (String) jobs.nextElement();
            String implName = c.getString(jobName + "." + PROP_PLUGIN);
            JobPlugin plugin =
                (JobPlugin) mJobPlugins.get(implName);

            if (plugin == null) {
                log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("CMSCORE_JOBS_CLASS_NOT_FOUND",
                        implName));
                throw new
                    EJobsException(CMS.getUserMessage("CMS_JOB_PLUGIN_NOT_FOUND", implName));
            }
            String classPath = plugin.getClassPath();

            // instantiate and init the job
            IJob job = null;

            try {
                job = (IJob)
                        Class.forName(classPath).newInstance();
                IConfigStore jconfig = c.getSubStore(jobName);

                job.init(this, jobName, implName, jconfig);

                // register the job
                mJobs.put(jobName, job);
            } catch (ClassNotFoundException e) {
                String errMsg = "JobsScheduler:: init()-" + e.toString();

                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()));
                throw new
                    EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", classPath));
            } catch (IllegalAccessException e) {
                String errMsg = "JobsScheduler:: init()-" + e.toString();

                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()));
                throw new
                    EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", classPath));
            } catch (InstantiationException e) {
                String errMsg = "JobsScheduler: init()-" + e.toString();

                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()));
                throw new
                    EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", classPath));
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INIT_ERROR", e.toString()));
                throw e;
            }
        }

        // are we enabled?
        if (mConfig.getBoolean(PROP_ENABLED, false) == true) {
            // start the daemon thread
            startDaemon();
        }
    }

    public Hashtable getPlugins() {
        return mJobPlugins;
    }

    public Hashtable getInstances() {
        return mJobs;
    }

    /**
     * when wake up:
     * . execute the scheduled job(s)
     * * if job still running from previous interval, skip it
     * . figure out when is the next wakeup time (every interval).  If
     *	 current wakup time runs over the interval, skip the missed interval(s)
     * . sleep till the next wakeup time
     */
    public void run() {
        long wokeupTime = 0;

        while (true) {
            // get time now
            Calendar cal = Calendar.getInstance();
            long rightNow = cal.getTime().getTime();
            long duration = 0;
            long second = cal.get(Calendar.SECOND);

            if (second != 1) { // scheduler needs adjustment
                // adjust to wake up at 1st second
                long milliSec = cal.get(Calendar.MILLISECOND);

                // possible to be at exactly second 1, millisecond 0,
                // just let it skip to next second, fine.
                duration = (60 - second) * 1000 + 1000 - milliSec;
                log(ILogger.LL_INFO,
                    "adjustment for cron behavior: sleep for " +
                    duration + " milliseconds");
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
                    System.out.println(e.toString());
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
			
            IJob job = null;

            for (Enumeration e = mJobs.elements(); e.hasMoreElements();) {
                job = (IJob) e.nextElement();

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
                    //	log(ILogger.LL_INFO, "show time for: "+job.getId());

                    // if previous thread still alive, skip
                    Thread jthread = (Thread) mJobThreads.get(job.getId());

                    if ((jthread == null) || (!jthread.isAlive())) {
                        Thread jobThread = new Thread((Runnable) job, job.getId());

                        jobThread.start();
                        // put into job thread control
                        mJobThreads.put(job.getId(), jobThread);
                    } else {
                        // previous thread still alive, log it
                        log(ILogger.LL_INFO, "Job " + job.getId() +
                            " still running...skipping this round");
                    }
                }
            } // for

        }
    }
   
    public IJobCron createJobCron(String cs) throws EBaseException {
        return new JobCron(cs);
    }

    /**
     * Is it time for the job?
     */
    protected boolean isShowTime(IJob job, Calendar now) {
        JobCron jcron = (JobCron) job.getJobCron();

        if (jcron == null) {
            // the impossible has happened
            log(ILogger.LL_INFO, "isShowTime(): jobcron null");
            return false;
        }

        /**
         * is it the right month?
         */
        Vector moy =
            jcron.getItem(jcron.CRON_MONTH_OF_YEAR).getElements();
		
        int cronMoy = jcron.MOY_cal2cron(now);

        if (jcron.isElement(cronMoy, moy) == false) {
            return false;
        }
        // is the right month!

        /**
         * is it the right date?
         */
        Vector dow = jcron.getItem(jcron.CRON_DAY_OF_WEEK).getElements();
        Vector dom = jcron.getItem(jcron.CRON_DAY_OF_MONTH).getElements();

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
        Vector hour = jcron.getItem(jcron.CRON_HOUR).getElements();

        if (jcron.isElement(now.get(Calendar.HOUR_OF_DAY), hour) == false) {
            return false;
        }
        // is the right hour!

        /**
         * is it the right minute?
         */
        Vector minute = jcron.getItem(jcron.CRON_MINUTE).getElements();

        if (jcron.isElement(now.get(Calendar.MINUTE), minute) == false) {
            return false;
        }
        // is the right minute!  We're on!

        return true;
    }

    /**
     * Retrieves id (name) of this subsystem.
     * @return name of the Jobs Scheduler subsystem
     */
    public String getId() {
        return (mId);
    }
  
    /**
     * Sets id string to this subsystem.
     * <p>
     * Use with caution.  Should not do it when sharing with others
     * @param id name to be applied to an Jobs Scheduler subsystem
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * creates and starts the daemon thread
     */
    public void startDaemon() {
        mScheduleThread = new Thread(this, "JobScheduler");
        log(ILogger.LL_INFO, "started Jobs Scheduler daemon thread");
        mScheduleThread.setDaemon(true);
        mScheduleThread.start();
    }

    /**
     * registers the administration servlet with the administration subsystem.
     */
    public void startup() throws EBaseException {
        //remove, already logged from S_ADMIN
        //String infoMsg = "Jobs Scheduler subsystem administration Servlet registered";
        //log(ILogger.LL_INFO, infoMsg);
    }

    /**
     * shuts down Jobs one by one. 
     * <P>
     */
    public void shutdown() {
        mJobPlugins.clear();
        mJobPlugins = null;
        mJobs.clear();
        mJobs = null;

        Enumeration enums = mJobThreads.keys();
        while (enums.hasMoreElements()) {
            String id = (String)enums.nextElement();
            Thread currthread = (Thread)mJobThreads.get(id);
            //if (currthread != null) 
            //  currthread.destroy();
        }

        mJobThreads.clear();
        mJobThreads = null;

        //if (mScheduleThread != null) 
              //  mScheduleThread.destroy();
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
     * Gets configuration parameters for the given 
     * job plugin.
     * @param implName Name of the job plugin.
     * @return Hashtable of required parameters.
     */
    public String[] getConfigParams(String implName)
        throws EJobsException {
        if (Debug.ON)
            Debug.trace("in getCofigParams()");

            // is this a registered implname?
        JobPlugin plugin = (JobPlugin) mJobPlugins.get(implName);

        if (plugin == null) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_JOBS_CLASS_NOT_FOUND", implName));
            if (Debug.ON)
                Debug.trace("Job plugin " + implName + " not found.");
            throw new EJobsException(CMS.getUserMessage("CMS_JOB_PLUGIN_NOT_FOUND",
                    implName));
        }

        // XXX can find an instance of this plugin in existing 
        // auth manager instantces to avoid instantiation just for this.

        // a temporary instance
        IJob jobInst = null;
        String className = plugin.getClassPath();

        if (Debug.ON)
            Debug.trace("className = " + className);
        try {
            jobInst = (IJob)
                    Class.forName(className).newInstance();
            if (Debug.ON)
                Debug.trace("class instantiated");
            return (jobInst.getConfigParams());
        } catch (InstantiationException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_JOBS_CREATE_NEW", e.toString()));
            if (Debug.ON)
                Debug.trace("class NOT instantiated: " + e.toString());
            throw new 
                EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", className));
        } catch (ClassNotFoundException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_JOBS_CREATE_NEW", e.toString()));
            if (Debug.ON)
                Debug.trace("class NOT instantiated: " + e.toString());
            throw new
                EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", className));
        } catch (IllegalAccessException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_JOBS_CREATE_NEW", e.toString()));
            if (Debug.ON)
                Debug.trace("class NOT instantiated: " + e.toString());
            throw new
                EJobsException(CMS.getUserMessage("CMS_JOB_LOAD_CLASS_FAILED", className));
        }
    }

    public void setInterval(int minutes) {
        mInterval = minutes * MINUTE_MILLI;
    }

    /**
     * logs an entry in the log file.
     */
    public void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
            level, msg);
    }

    public Hashtable getJobPlugins() {
        return mJobPlugins;
    }
}
