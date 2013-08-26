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

package org.dogtagpki.server.tps.connection;

import com.netscape.cmscore.dbs.Database;

/**
 * This class implements in-memory connection database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class ConnectionDatabase extends Database<ConnectionRecord> {

    public ConnectionDatabase() {
        super("Connection");

        // add sample records
        try {
            ConnectionRecord record1 = new ConnectionRecord();
            record1.setID("connection1");
            record1.setStatus("ENABLED");
            record1.setContents("name=connection1\nparam=value");
            addRecord(record1);

            ConnectionRecord record2 = new ConnectionRecord();
            record2.setID("connection2");
            record2.setStatus("DISABLED");
            record2.setContents("name=connection2\nparam=value");
            addRecord(record2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addRecord(ConnectionRecord connectionRecord) throws Exception {
        addRecord(connectionRecord.getID(), connectionRecord);
    }

    public void updateRecord(ConnectionRecord connectionRecord) throws Exception {
        updateRecord(connectionRecord.getID(), connectionRecord);
    }
}
