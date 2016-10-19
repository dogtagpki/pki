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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.rest.AccountService;

import com.netscape.certsrv.account.AccountInfo;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;

/**
 * @author Endi S. Dewata
 */
public class TPSAccountService extends AccountService {

    IConfigStore configStore = CMS.getConfigStore();

    @Override
    public AccountInfo createAccountInfo() {

        AccountInfo accountInfo = super.createAccountInfo();

        try {
            // determine accessible components based on roles
            Collection<String> components = new HashSet<String>();

            Collection<String> roles = accountInfo.getRoles();

            if (roles.contains("Administrators")) {
                String values = configStore.getString("target.configure.list", "");
                if (!StringUtils.isEmpty(values)) {
                    components.addAll(Arrays.asList(values.split(",")));
                }

                // admin always has access to general configuration and audit logging
                components.add("Generals");
                components.add("Audit_Logging");

            }

            if (roles.contains("TPS Agents")) {
                String values = configStore.getString("target.agent_approve.list", "");
                if (!StringUtils.isEmpty(values)) {
                    components.addAll(Arrays.asList(values.split(",")));
                }
            }

            accountInfo.setAttribute("components", StringUtils.join(components, ","));

        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException(e);
        }

        return accountInfo;
    }
}
