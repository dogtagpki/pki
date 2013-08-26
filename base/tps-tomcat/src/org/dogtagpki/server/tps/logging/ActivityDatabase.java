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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.logging;

import java.util.Date;

import com.netscape.cmscore.dbs.Database;

/**
 * This class implements in-memory activity database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class ActivityDatabase extends Database<ActivityRecord> {

    public ActivityDatabase() {
        super("Activity");

        // add sample records
        try {
            ActivityRecord record1 = new ActivityRecord();
            record1.setID("activity1");
            record1.setTokenID("token1");
            record1.setUserID("user1");
            record1.setIp("192.168.1.1");
            record1.setOperation("enroll");
            record1.setResult("success");
            addRecord(record1);

            ActivityRecord record2 = new ActivityRecord();
            record2.setID("activity2");
            record2.setTokenID("token2");
            record2.setUserID("user2");
            record2.setIp("192.168.1.2");
            record2.setOperation("enroll");
            record2.setResult("failed");
            addRecord(record2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addRecord(ActivityRecord activityRecord) throws Exception {
        activityRecord.setDate(new Date());

        addRecord(activityRecord.getID(), activityRecord);
    }

    public void updateRecord(ActivityRecord activityRecord) throws Exception {
        updateRecord(activityRecord.getID(), activityRecord);
    }
}
