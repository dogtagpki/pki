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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.cmscore.dbs.LDAPDatabase;

/**
 * This class implements in-memory activity database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class TPSCertDatabase extends LDAPDatabase<TPSCertRecord> {

    public TPSCertDatabase(IDBSubsystem dbSubsystem, String baseDN) throws EBaseException {
        super("Certificate", dbSubsystem, baseDN, TPSCertRecord.class);
    }

    @Override
    public void addRecord(String id, TPSCertRecord certRecord) throws Exception {
        certRecord.setCreateTime(new Date());

        super.addRecord(id, certRecord);
    }

    @Override
    public void updateRecord(String id, TPSCertRecord certRecord) throws Exception {
        certRecord.setModifyTime(new Date());

        super.updateRecord(id, certRecord);
    }

    @Override
    public String createDN(String id) {
        return "cn=" + id + "," + baseDN;
    }

    @Override
    public String createFilter(String filter) {
        return "(id=*)";
    }
}
