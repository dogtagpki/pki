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

import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;

/**
 * class representing one Job cron item
 * <p>
 * here, an "item" refers to one of the 5 fields in a cron string; "element" refers to any comma-deliminated element in
 * an "item"...which includes both numbers and '-' separated ranges.
 * <p>
 * for each of the 5 cron fields, it's represented as a CronItem
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CronItem {
    protected static final String ALL = "*";
    protected static final String DELIM = ",";
    protected static final String RANGE = "-";
    private ILogger mLogger = CMS.getLogger();

    int mMin; // minimum
    int mMax; // maximum

    // store all elements in a field.
    // elements can either be numbers or ranges (CronRange)
    protected Vector<CronRange> mElements = new Vector<CronRange>();

    public CronItem(int min, int max) {
        mMin = min;
        mMax = max;
    }

    /**
     * parses and sets a string cron item
     *
     * @param sItem the string representing an item of a cron string.
     *            item can be potentially comma separated with ranges specified
     *            with '-'s
     */
    public void set(String sItem) throws EBaseException {

        if (sItem.equals(ALL)) {
            //			System.out.println("CronItem set(): item is ALL");
            CronRange cr = new CronRange();

            cr.setBegin(mMin);
            cr.setEnd(mMax);
            mElements.addElement(cr);
        } else {
            // break comma-separated elements
            StringTokenizer st = new StringTokenizer(sItem, DELIM);

            while (st.hasMoreTokens()) {
                String tok = st.nextToken();
                // elements could be ranges (separated by '-')
                int r = tok.indexOf(RANGE);

                if (r != -1) {
                    // potential range
                    String sBegin = tok.substring(0, r);
                    int begin = 0;
                    int end = 0;

                    try {
                        begin = Integer.parseInt(sBegin);
                    } catch (NumberFormatException e) {
                        // throw ...
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_JOBS_INVALID_TOKEN", tok, e.toString()));
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
                    }
                    String sEnd = tok.substring(r + 1, tok.length());

                    try {
                        end = Integer.parseInt(sEnd);
                    } catch (NumberFormatException e) {
                        // throw ...
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_JOBS_INVALID_TOKEN", tok, e.toString()));
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
                    }
                    // got both begin and end for range
                    CronRange cr = new CronRange();

                    cr.setBegin(begin);
                    cr.setEnd(end);
                    // check range
                    if (!cr.isValidRange(mMin, mMax)) {
                        // throw...
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_JOBS_INVALID_RANGE",
                                        tok));
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
                    }
                    //					System.out.println("CronItem set(): adding a range");
                    mElements.addElement(cr);
                } else {
                    // number element, begin and end are the same
                    try {
                        CronRange cr = new CronRange();
                        int num = Integer.parseInt(tok);

                        cr.setBegin(num);
                        cr.setEnd(num);
                        // check range
                        if (!cr.isValidRange(mMin, mMax)) {
                            // throw...
                            log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSCORE_JOBS_INVALID_MIN_MAX_RANGE", Integer.toString(mMin),
                                            Integer.toString(mMax)));
                            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
                        }
                        //						System.out.println("CronItem set(): adding a number");
                        mElements.addElement(cr);
                    } catch (NumberFormatException e) {
                        // throw...
                        log(ILogger.LL_FAILURE,
                                "invalid item in cron: " + tok);
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_JOB_CRON"));
                    }
                }
            }
        }
    }

    /**
     * get the vector stuffed with elements where each element is
     * represented as CronRange
     *
     * @return a vector of CronRanges
     */
    public Vector<CronRange> getElements() {
        return mElements;
    }

    /**
     * logs an entry in the log file.
     */
    protected void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                level, "jobs/CronItem: " + msg);
    }
}
