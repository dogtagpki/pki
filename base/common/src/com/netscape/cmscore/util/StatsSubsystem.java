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
package com.netscape.cmscore.util;

import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.certsrv.util.StatsEvent;

/**
 * A class represents a internal subsystem. This subsystem
 * can be loaded into cert server kernel to perform
 * statistics collection.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class StatsSubsystem implements IStatsSubsystem {
    private String mId = null;
    private StatsEvent mAllTrans = new StatsEvent(null);
    private Date mStartTime = new Date();
    private Hashtable<String, Vector<StatsMilestone>> mHashtable = new Hashtable<String, Vector<StatsMilestone>>();

    /**
     * Constructs a certificate server.
     */
    public StatsSubsystem() {
        super();
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return mId;
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * Initializes this subsystem with the given
     * configuration store.
     * It first initializes resident subsystems,
     * and it loads and initializes loadable
     * subsystem specified in the configuration
     * store.
     * <P>
     * Note that individual subsystem should be initialized in a separated thread if it has dependency on the
     * initialization of other subsystems.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     */
    public synchronized void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
    }

    public Date getStartTime() {
        return mStartTime;
    }

    public void startTiming(String id) {
        startTiming(id, false /* not the main */);
    }

    public void startTiming(String id, boolean mainAction) {
        Thread t = Thread.currentThread();
        Vector<StatsMilestone> milestones = null;
        if (mHashtable.containsKey(t.toString())) {
            milestones = mHashtable.get(t.toString());
        } else {
            milestones = new Vector<StatsMilestone>();
            mHashtable.put(t.toString(), milestones);
        }
        long startTime = CMS.getCurrentDate().getTime();
        StatsEvent currentST = null;
        for (int i = 0; i < milestones.size(); i++) {
            StatsMilestone se = milestones.elementAt(i);
            if (currentST == null) {
                currentST = mAllTrans.getSubEvent(se.getId());
            } else {
                currentST = currentST.getSubEvent(se.getId());
            }
        }
        if (currentST == null) {
            if (!mainAction) {
                return; /* ignore none main action */
            }
            currentST = mAllTrans;
        }
        StatsEvent newST = currentST.getSubEvent(id);
        if (newST == null) {
            newST = new StatsEvent(currentST);
            newST.setName(id);
            currentST.addSubEvent(newST);
        }
        milestones.addElement(new StatsMilestone(id, startTime, newST));
    }

    public void endTiming(String id) {
        long endTime = CMS.getCurrentDate().getTime();
        Thread t = Thread.currentThread();
        if (!mHashtable.containsKey(t.toString())) {
            return; /* error */
        }
        Vector<StatsMilestone> milestones = mHashtable.get(t.toString());
        if (milestones.size() == 0) {
            return; /* error */
        }
        StatsMilestone last = milestones.remove(milestones.size() - 1);
        StatsEvent st = last.getStatsEvent();
        st.incNoOfOperations(1);
        st.incTimeTaken(endTime - last.getStartTime());
        if (milestones.size() == 0) {
            mHashtable.remove(t.toString());
        }
    }

    public void resetCounters() {
        mStartTime = CMS.getCurrentDate();
        mAllTrans.resetCounters();
    }

    public StatsEvent getMainStatsEvent() {
        return mAllTrans;
    }

    public void startup() throws EBaseException {
    }

    /**
     * Stops this system.
     */
    public synchronized void shutdown() {
    }

    /*
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return null;
    }
}

class StatsMilestone {
    private String mId = null;
    private long mStartTime = 0;
    private StatsEvent mST = null;

    public StatsMilestone(String id, long startTime, StatsEvent st) {
        mId = id;
        mStartTime = startTime;
        mST = st;
    }

    public String getId() {
        return mId;
    }

    public long getStartTime() {
        return mStartTime;
    }

    public StatsEvent getStatsEvent() {
        return mST;
    }
}
