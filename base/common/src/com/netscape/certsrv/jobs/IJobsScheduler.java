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
package com.netscape.certsrv.jobs;

import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;

/**
 * An interface that represents the job scheduler component. A JobScheduler
 * is a daemon thread that handles scheduled jobs like cron would
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
 * @version $Revision$, $Date$
 */
public interface IJobsScheduler extends ISubsystem {
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

    /**
     * Retrieves all the job implementations.
     * 
     * @return a Hashtable of available job plugin implementations
     */
    public Hashtable<String, JobPlugin> getPlugins();

    /**
     * Retrieves all the job instances.
     * 
     * @return a Hashtable of job instances
     */
    public Hashtable<String, IJob> getInstances();

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
            throws EJobsException;

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
    public void log(int level, String msg);

    /**
     * Sets daemon's wakeup interval.
     * 
     * @param minutes time in minutes that is to be the frequency of
     *            JobsScheduler wakeup call.
     */
    public void setInterval(int minutes);

    /**
     * Starts up the JobsScheduler daemon. Usually called from the
     * initialization method when it's successfully initialized.
     */
    public void startDaemon();

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
    public IJobCron createJobCron(String cs) throws EBaseException;
}
