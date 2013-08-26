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

package org.dogtagpki.server.tps.cert;

import java.util.Date;

import com.netscape.cmscore.dbs.Database;

/**
 * This class implements in-memory activity database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class TPSCertDatabase extends Database<TPSCertRecord> {

    public TPSCertDatabase() {
        super("Certificate");

        // add sample records
        try {
            TPSCertRecord record1 = new TPSCertRecord();
            record1.setID("cert1");
            record1.setSerialNumber("16");
            record1.setSubject("cn=someone");
            record1.setTokenID("TOKEN0001");
            record1.setKeyType("something");
            record1.setStatus("active");
            record1.setUserID("user1");
            record1.setCreateTime(new Date());
            record1.setModifyTime(new Date());
            addRecord(record1);

            TPSCertRecord record2 = new TPSCertRecord();
            record2.setID("cert2");
            record2.setSerialNumber("17");
            record2.setSubject("cn=someone");
            record2.setTokenID("TOKEN0002");
            record2.setKeyType("something");
            record2.setStatus("revoked");
            record2.setUserID("user2");
            record2.setCreateTime(new Date());
            record2.setModifyTime(new Date());
            addRecord(record2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addRecord(TPSCertRecord certRecord) throws Exception {
        certRecord.setCreateTime(new Date());

        addRecord(certRecord.getID(), certRecord);
    }

    public void updateRecord(TPSCertRecord certRecord) throws Exception {
        updateRecord(certRecord.getID(), certRecord);
    }
}
