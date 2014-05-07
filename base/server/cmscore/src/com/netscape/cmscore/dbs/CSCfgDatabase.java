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

package com.netscape.cmscore.dbs;

import java.security.Principal;
import java.util.Arrays;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cms.realm.PKIPrincipal;


/**
 * This class implements in-memory database which is stored in CS.cfg.
 *
 * @author Endi S. Dewata
 */
public class CSCfgDatabase<E extends CSCfgRecord> extends Database<E> {

    public IConfigStore configStore = CMS.getConfigStore();
    public String substoreName;

    public CSCfgDatabase(String name, String substoreName) {
        super(name);
        this.substoreName = substoreName;
    }

    public boolean requiresApproval() throws EBaseException {
        String value = configStore.getString("target.agent_approve.list", "");
        return Arrays.asList(StringUtils.split(value, ",")).contains(substoreName);
    }

    public boolean canApprove(Principal principal) {
        if (!(principal instanceof PKIPrincipal)) {
            return false;
        }

        PKIPrincipal pkiPrincipal = (PKIPrincipal)principal;
        return pkiPrincipal.hasRole("TPS Agents");
    }

    public String getRecordStatus(String recordID) throws EBaseException {
        return configStore.getString("config." + substoreName + "." + recordID + ".state", "Disabled");
    }

    public void setRecordStatus(String recordID, String status) throws EBaseException {
        configStore.put("config." + substoreName + "." + recordID + ".state", status);
        configStore.put("config." + substoreName + "." + recordID + ".timestamp",
                "" + (System.currentTimeMillis() * 1000));
    }

    public void removeRecordStatus(String recordID) {
        configStore.remove("config." + substoreName + "." + recordID + ".state");
        configStore.remove("config." + substoreName + "." + recordID + ".timestamp");
    }
}
