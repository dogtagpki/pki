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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;

/**
 * An interface to be implemented from for a job to be scheduled by the Jobs
 * Scheduler.
 * 
 * @version $Revision$, $Date$
 */
public interface IJob {

    /**
     * Initialize from the configuration file.
     * 
     * @param id String name of this instance
     * @param implName string name of this implementation
     * @param config configuration store for this instance
     * @exception EBaseException any initilization failure
     */
    public void init(ISubsystem owner, String id, String implName,
            IConfigStore config) throws EBaseException;

    /**
     * tells if the job is enabled
     * 
     * @return a boolean value indicating whether the job is enabled or not
     */
    public boolean isEnabled();

    /**
     * set instance id.
     * 
     * @param id String id of the instance
     */
    public void setId(String id);

    /**
     * get instance id.
     * 
     * @return a String identifier
     */
    public String getId();

    /**
     * get cron string associated with this job
     * 
     * @return a JobCron object that represents the schedule of this job
     */
    public IJobCron getJobCron();

    /**
     * Returns a list of configuration parameter names. The list is passed to
     * the configuration console so instances of this implementation can be
     * configured through the console.
     * 
     * @return String array of configuration parameter names.
     */
    public String[] getConfigParams();

    /**
     * gets the plugin name of this job.
     * 
     * @return a String that is the name of this implementation
     */
    public String getImplName();

    /**
     * Gets the configuration substore used by this job
     * 
     * @return configuration store
     */
    public IConfigStore getConfigStore();
}
