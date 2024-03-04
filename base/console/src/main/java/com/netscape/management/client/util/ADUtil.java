/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2008 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
/**
 * This class provides utility methods for dealing with Active Directory
 * data.
 */
package com.netscape.management.client.util;

import java.util.Date;

public class ADUtil {
    /**
     * Some of the AD date/time attribute values are in Windows FILETIME
     * format.  This is a 64-bit value which is 100's of nanoseconds since 1/1/1601.
     * Java uses 64-bit long - milliseconds since 1/1/1970
     * AD_EPOCH is the difference in milliseconds between the FILETIME epoch and
     * the java time epoch.
     */
    static final long AD_EPOCH = 11644473600000L; /* millisecs */
    static final long ACCOUNT_NEVER_EXPIRES = 9223372036854775807L;

    static public Date convertToJavaDateTime(String adtimestr) {
        if (adtimestr == null) {
            return null;
        }
        Date dt = new Date();
        long lts = 0;
        try {
             lts = Long.parseLong(adtimestr);
        } catch (NumberFormatException nfe) {
            Debug.print(0, "Invalid datetime from AD " + adtimestr);
            return null;
        }
        if ((lts == 0) || (lts == ACCOUNT_NEVER_EXPIRES)) {
            dt.setTime(-1L);
        } else {
            dt.setTime(lts/10000 - AD_EPOCH);
        }
        return dt;
    }
    
    static public String convertToFileTime(Date dt) {
        String val;
        if (dt == null) {
            return null;
        }
        long lts = dt.getTime();
        
        if (lts == -1L) {
            val = Long.toString(ACCOUNT_NEVER_EXPIRES);
        } else {
            val = Long.toString((lts + AD_EPOCH)*10000);
        }
        
        return val;
    }
    
    static public boolean neverExpires(Date dt) {
        if (dt == null) {
            return true;
        }
        return dt.getTime() == -1L;
    }
}
