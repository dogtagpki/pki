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


import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.base.*;

import java.util.*;
import java.lang.*;


/**
 * class representing one Job cron information
 * <p>here, an "item" refers to one of the 5 fields in a cron string;
 * "element" refers to any comma-deliminated element in an
 * "item"...which includes both numbers and '-' separated ranges.
 * A cron string in the configuration takes the following format:
 * <i>minute (0-59),
 * hour (0-23),
 * day of the month (1-31),
 * month of the year (1-12),
 * day of the week (0-6 with 0=Sunday)</i>
 * <p>
 * e.g. jobsScheduler.job.rnJob1.cron=30 11,23 * * 1-5
 * In this example, the job "rnJob1" will be executed from Monday
 * through Friday, at 11:30am and 11:30pm.
 * <p>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IJobCron {
    /**
     * constant that represents the configuration parameter
     * "cron" for the job that this JobCron is associated with.  The
     * value of which should conform to the cron format specified above.
     */
    public static final String PROP_CRON = "cron";

}
