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
import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.jobs.IJobCron;
import com.netscape.certsrv.logging.ILogger;

/**
 * class representing one Job cron information
 * <p>
 * here, an "item" refers to one of the 5 fields in a cron string; "element" refers to any comma-deliminated element in
 * an "item"...which includes both numbers and '-' separated ranges. A cron string in the configuration takes the
 * following format: <i>minute (0-59), hour (0-23), day of the month (1-31), month of the year (1-12), day of the week
 * (0-6 with 0=Sunday)</i>
 * <p>
 * e.g. jobsScheduler.job.rnJob1.cron=30 11,23 * * 1-5 In this example, the job "rnJob1" will be executed from Monday
 * through Friday, at 11:30am and 11:30pm.
 * <p>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class JobCron implements IJobCron {

    /**
     * CRON_MINUTE, CRON_HOUR, CRON_DAY_OF_MONTH, CRON_MONTH_OF_YEAR,
     * and CRON_DAY_OF_WEEK are to be used in <b>getItem()</b> to
     * retrieve the corresponding <b>CronItem</b>
     */
    public static final String CRON_MINUTE = "minute";
    public static final String CRON_HOUR = "hour";
    public static final String CRON_DAY_OF_MONTH = "dom";
    public static final String CRON_MONTH_OF_YEAR = "moy";
    public static final String CRON_DAY_OF_WEEK = "dow";
    private ILogger mLogger = CMS.getLogger();

    String mCronString = null;

    CronItem cMinute = null;
    CronItem cHour = null;
    CronItem cDOM = null;
    CronItem cMOY = null;
    CronItem cDOW = null;

    public JobCron(String cronString)
            throws EBaseException {
        mCronString = cronString;

        // create all 5 items in the cron
        cMinute = new CronItem(0, 59);
        cHour = new CronItem(0, 23);
        cDOM = new CronItem(1, 31);
        cMOY = new CronItem(1, 12);
        cDOW = new CronItem(0, 6); // 0=Sunday

        cronToVals(mCronString);
    }

    private void cronToVals(String cronString)
            throws EBaseException {
        StringTokenizer st = new StringTokenizer(cronString);

        String sMinute = null;
        String sHour = null;
        String sDayOMonth = null;
        String sMonthOYear = null;
        String sDayOWeek = null;

        try {
            if (st.hasMoreTokens()) {
                sMinute = st.nextToken();
                cMinute.set(sMinute);
            }
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_JOBS_INVALID_MIN", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
        }

        try {
            if (st.hasMoreTokens()) {
                sHour = st.nextToken();
                cHour.set(sHour);
            }
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INVALID_HOUR", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
        }

        if (st.hasMoreTokens()) {
            sDayOMonth = st.nextToken();
            //			cDOM.set(sDayOMonth);
        }

        try {
            if (st.hasMoreTokens()) {
                sMonthOYear = st.nextToken();
                cMOY.set(sMonthOYear);
            }
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INVALID_MONTH", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
        }

        if (st.hasMoreTokens()) {
            sDayOWeek = st.nextToken();
            //			cDOW.set(sDayOWeek);
        }

        /**
         * day-of-month or day-of-week, or both?
         * if only one of them is '*', the non '*' one prevails,
         * the '*' one will remain empty (no elements)
         */
        // day-of-week
        if ((sDayOMonth != null)
                && sDayOMonth.equals(CronItem.ALL) && (sDayOWeek != null) && !sDayOWeek.equals(CronItem.ALL)) {
            try {
                cDOW.set(sDayOWeek);
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INVALID_DAY_OF_WEEK", e.toString()));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
            }
        } else if ((sDayOMonth != null)
                && !sDayOMonth.equals(CronItem.ALL) && (sDayOWeek != null) && sDayOWeek.equals(CronItem.ALL)) {
            try {
                cDOM.set(sDayOMonth);
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INVALID_DAY_OF_MONTH", e.toString()));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
            }
        } else { // if both '*', every day, if neither is '*', do both
            try {
                if (sDayOWeek != null) {
                    cDOW.set(sDayOWeek);
                }
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INVALID_DAY_OF_WEEK", e.toString()));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
            }
            try {
                if (sDayOMonth != null) {
                    cDOM.set(sDayOMonth);
                }
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_JOBS_INVALID_DAY_OF_MONTH", e.toString()));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
            }
        }
    }

    /**
     * retrieves the cron item
     *
     * @param item name of the item. must be one of the <b>CRON_*</b>
     *            strings defined in this class
     * @return an instance of the CronItem class which represents the
     *         requested cron item
     */
    public CronItem getItem(String item) {
        if (item.equals(CRON_MINUTE)) {
            return cMinute;
        } else if (item.equals(CRON_HOUR)) {
            return cHour;
        } else if (item.equals(CRON_DAY_OF_MONTH)) {
            return cDOM;
        } else if (item.equals(CRON_MONTH_OF_YEAR)) {
            return cMOY;
        } else if (item.equals(CRON_DAY_OF_WEEK)) {
            return cDOW;
        } else {
            // throw...
        }

        return null;
    }

    /**
     * Does the element fit any element in the item
     *
     * @param element the element of "now" in cron format
     * @param item the item consists of a vector of elements
     * @return boolean (true/false) on whether the element is one of
     *         the elements in the item
     */
    boolean isElement(int element, Vector<CronRange> item) {
        // loop through all of the elements of an item
        for (Enumeration<CronRange> e = item.elements(); e.hasMoreElements();) {
            CronRange cElement = e.nextElement();

            // is a number
            if (cElement.getBegin() == cElement.getEnd()) {
                if (element == cElement.getBegin()) {
                    return true;
                }
            } else { // is a range
                if ((element >= cElement.getBegin()) &&
                        (element <= cElement.getEnd())) {
                    return true;
                }
            }
        }
        // no fit
        return false;
    }

    /**
     * convert the day of the week representation from Calendar to
     * cron
     *
     * @param time the Calendar value represents a moment of time
     * @return an integer value that represents a cron Day-Of-Week
     *         element
     */
    public int DOW_cal2cron(Calendar time) {
        int calDow = time.get(Calendar.DAY_OF_WEEK);
        int cronDow = 0; // default should never be used

        // convert the Calendar representation of dow to the cron one
        switch (calDow) {
        case Calendar.SUNDAY:
            cronDow = 0;
            break;

        case Calendar.MONDAY:
            cronDow = 1;
            break;

        case Calendar.TUESDAY:
            cronDow = 2;
            break;

        case Calendar.WEDNESDAY:
            cronDow = 3;
            break;

        case Calendar.THURSDAY:
            cronDow = 4;
            break;

        case Calendar.FRIDAY:
            cronDow = 5;
            break;

        case Calendar.SATURDAY:
            cronDow = 6;
            break;

        default:
            throw new IllegalArgumentException();
        }

        return cronDow;
    }

    /**
     * convert the month of year representation from Calendar to cron
     *
     * @param time the Calendar value represents a moment of time
     * @return an integer value that represents a cron Month-Of-Year
     *         element
     */
    public int MOY_cal2cron(Calendar time) {
        int calMoy = time.get(Calendar.MONTH);
        int cronMoy = 0;

        // convert the Calendar representation of moy to the cron one
        switch (calMoy) {
        case Calendar.JANUARY:
            cronMoy = 1;
            break;

        case Calendar.FEBRUARY:
            cronMoy = 2;
            break;

        case Calendar.MARCH:
            cronMoy = 3;
            break;

        case Calendar.APRIL:
            cronMoy = 4;
            break;

        case Calendar.MAY:
            cronMoy = 5;
            break;

        case Calendar.JUNE:
            cronMoy = 6;
            break;

        case Calendar.JULY:
            cronMoy = 7;
            break;

        case Calendar.AUGUST:
            cronMoy = 8;
            break;

        case Calendar.SEPTEMBER:
            cronMoy = 9;
            break;

        case Calendar.OCTOBER:
            cronMoy = 10;
            break;

        case Calendar.NOVEMBER:
            cronMoy = 11;
            break;

        case Calendar.DECEMBER:
            cronMoy = 12;
            break;

        default:
            throw new IllegalArgumentException();
        }

        return cronMoy;
    }

    /**
     * logs an entry in the log file.
     */
    protected void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                level, msg);
    }
}
