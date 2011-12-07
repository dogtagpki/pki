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

/**
 * This class represents a job plugin registered with the JobScheduler. A Job
 * plugin can be instantiated into a Job instance and scheduled by the
 * JobScheduler to run at a scheduled interval
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public class JobPlugin {
    /**
     * The plugin name of this job
     */
    protected String mId = null;
    /**
     * The Java class name of this job plugin. e.g.
     * com.netscape.cms.RenewalNotificationJob
     */
    protected String mClassPath = null;

    /*
     * Seems to be unused, should be removed
     */
    // protected Class mClass = null;

    /**
     * Constructor for a Job plugin.
     * 
     * @param id job plugin name
     * @param classPath the Java class name of this job plugin
     */
    public JobPlugin(String id, String classPath) {
        mId = id;
        mClassPath = classPath;
    }

    /**
     * get the job plugin name
     * 
     * @return the name of this job plugin
     */
    public String getId() {
        return mId;
    }

    /**
     * get the Java class name
     * 
     * @return the Java class name of this plugin
     */
    public String getClassPath() {
        return mClassPath;
    }
}
