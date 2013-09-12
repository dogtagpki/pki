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

package org.dogtagpki.server.tps.token;

import java.util.Date;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.cmscore.dbs.LDAPDatabase;

/**
 * @author Endi S. Dewata
 */
public class TokenDatabase extends LDAPDatabase<TokenRecord> {

    public TokenDatabase(IDBSubsystem dbSubsystem, String baseDN) throws EBaseException {
        super("Token", dbSubsystem, baseDN, TokenRecord.class);
    }

    @Override
    public void addRecord(String id, TokenRecord tokenRecord) throws Exception {
        tokenRecord.setStatus("ENABLED");
        tokenRecord.setCreateTimestamp(new Date());

        super.addRecord(id, tokenRecord);
    }

    @Override
    public void updateRecord(String id, TokenRecord tokenRecord) throws Exception {
        tokenRecord.setModifyTimestamp(new Date());

        super.updateRecord(id, tokenRecord);
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
