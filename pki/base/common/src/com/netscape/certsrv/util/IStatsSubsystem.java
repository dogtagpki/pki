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


import java.util.*;
import com.netscape.certsrv.base.*;


/**
 * A class represents a internal subsystem. This subsystem
 * can be loaded into cert server kernel to perform
 * statistics collection.
 * <P>
 * 
 * @author thomask
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IStatsSubsystem extends ISubsystem
{
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
