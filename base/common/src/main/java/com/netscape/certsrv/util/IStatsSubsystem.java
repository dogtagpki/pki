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

import java.util.Date;

import com.netscape.certsrv.base.ISubsystem;

/**
 * A class represents a internal subsystem. This subsystem
 * can be loaded into cert server kernel to perform
 * statistics collection.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public interface IStatsSubsystem extends ISubsystem {
    public static final String ID = "stats";
    /**
     * Retrieves the start time since startup or
     * clearing of statistics.
     */
    public Date getStartTime();

    /**
     * Starts timing of a operation.
     */
    public void startTiming(String id);

    public void startTiming(String id, boolean main);

    /**
     * Stops timing of a operation.
     */
    public void endTiming(String id);

    /**
     * Resets counters.
     */
    public void resetCounters();

    /**
     * Resets all internal counters.
     */
    public StatsEvent getMainStatsEvent();
}
