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
package com.netscape.certsrv.util;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

/**
 * A statistics transaction.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class StatsEvent {
    private String mName = null;
    private long mMin = -1;
    private long mMax = -1;
    private long mTimeTaken = 0;
    private long mTimeTakenSqSum = 0;
    private long mNoOfOperations = 0;
    private Map<String,StatsEvent> mSubEvents = new HashMap<String,StatsEvent>();
    private StatsEvent mParent = null;

    public StatsEvent(StatsEvent parent) {
        mParent = parent;
    }

    public void setName(String name) {
        mName = name;
    }

    /**
     * Retrieves Transaction name.
     */
    public String getName() {
        return mName;
    }

    public void addSubEvent(StatsEvent st) {
        mSubEvents.put(st.getName(), st);
    }

    /**
     * Retrieves a list of sub transaction names.
     */
    public Enumeration<String> getSubEventNames() {
        Vector<String> names = new Vector<String>();
        names.addAll(mSubEvents.keySet());
        return names.elements();
    }

    /**
     * Retrieves a sub transaction.
     */
    public StatsEvent getSubEvent(String name) {
        return mSubEvents.get(name);
    }

    public void resetCounters() {
        mMin = -1;
        mMax = -1;
        mNoOfOperations = 0;
        mTimeTaken = 0;
        mTimeTakenSqSum = 0;
        for (StatsEvent c : mSubEvents.values()) {
                c.resetCounters();
        }
    }

    public long getMax() {
        return mMax;
    }

    public long getMin() {
        return mMin;
    }

    public void incNoOfOperations(long c) {
        mNoOfOperations += c;
    }

    public long getTimeTakenSqSum() {
        return mTimeTakenSqSum;
    }

    public long getPercentage() {
        if (mParent == null || mParent.getTimeTaken() == 0) {
            return 100;
        } else {
            return (mTimeTaken * 100 / mParent.getTimeTaken());
        }
    }

    public long getStdDev() {
        if (getNoOfOperations() == 0) {
            return 0;
        } else {
            long a = getTimeTakenSqSum();
            long b = (-2 * getAvg() * getTimeTaken());
            long c = getAvg() * getAvg() * getNoOfOperations();
            return (long) Math.sqrt(((double) (a + b + c)) / getNoOfOperations());
        }
    }

    public long getAvg() {
        if (mNoOfOperations == 0) {
            return -1;
        } else {
            return mTimeTaken / mNoOfOperations;
        }
    }

    /**
     * Retrieves number of operations performed.
     */
    public long getNoOfOperations() {
        return mNoOfOperations;
    }

    public void incTimeTaken(long c) {
        if (mMin == -1) {
            mMin = c;
        } else {
            if (c < mMin) {
                mMin = c;
            }
        }
        if (mMax == -1) {
            mMax = c;
        } else {
            if (c > mMax) {
                mMax = c;
            }
        }
        mTimeTaken += c;
        mTimeTakenSqSum += (c * c);
    }

    /**
     * Retrieves total time token in msec.
     */
    public long getTimeTaken() {
        return mTimeTaken;
    }
}
