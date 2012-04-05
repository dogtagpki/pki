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

/**
 * class representing one Job cron element
 * <p>
 * here, an "item" refers to one of the 5 fields in a cron string; "element" refers to any comma-deliminated element in
 * an "item"...which includes both numbers and '-' separated ranges.
 * <p>
 * an Element can contain either an integer number or a range specified as CronRange. In case of integer numbers, begin
 * and end are of the same value
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CronRange {
    int mBegin = 0;
    int mEnd = 0;

    public CronRange() {
    }

    /**
     * sets the lower boundary value of the range
     */
    public void setBegin(int i) {
        mBegin = i;
    }

    /**
     * gets the lower boundary value of the range
     */
    public int getBegin() {
        return mBegin;
    }

    /**
     * sets the higher boundary value of the range
     */
    public void setEnd(int i) {
        mEnd = i;
    }

    /**
     * gets the higher boundary value of the range
     */
    public int getEnd() {
        return mEnd;
    }

    /**
     * checks to see if the lower and higher boundary values are
     * within the min/max.
     *
     * @param min the minimum value one can specify in this field
     * @param max the maximum value one can specify in this field
     * @return a boolean (true/false) on whether the begin/end values
     *         are within the min/max passed in the params
     */
    public boolean isValidRange(int min, int max) {
        if ((mEnd < mBegin) ||
                (mBegin < min) ||
                (mEnd > max))
            return false;
        else
            return true;
    }
}
