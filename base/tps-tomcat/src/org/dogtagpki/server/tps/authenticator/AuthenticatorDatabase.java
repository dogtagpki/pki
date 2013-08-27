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

package org.dogtagpki.server.tps.authenticator;

import com.netscape.cmscore.dbs.Database;

/**
 * This class implements in-memory connection database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class AuthenticatorDatabase extends Database<AuthenticatorRecord> {

    public AuthenticatorDatabase() {
        super("Authenticator");

        // add sample records
        try {
            AuthenticatorRecord record1 = new AuthenticatorRecord();
            record1.setID("authenticator1");
            record1.setStatus("ENABLED");
            record1.setContents("name=authenticator1\nparam=value");
            addRecord(record1);

            AuthenticatorRecord record2 = new AuthenticatorRecord();
            record2.setID("authenticator2");
            record2.setStatus("DISABLED");
            record2.setContents("name=authenticator2\nparam=value");
            addRecord(record2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addRecord(AuthenticatorRecord authenticatorRecord) throws Exception {
        addRecord(authenticatorRecord.getID(), authenticatorRecord);
    }

    public void updateRecord(AuthenticatorRecord authenticatorRecord) throws Exception {
        updateRecord(authenticatorRecord.getID(), authenticatorRecord);
    }
}
