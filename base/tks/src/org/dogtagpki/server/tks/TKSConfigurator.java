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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tks;

import java.util.Collection;

import com.netscape.certsrv.system.DatabaseSetupRequest;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.tks.TKSAuthority;

public class TKSConfigurator extends Configurator {

    public TKSConfigurator(CMSEngine engine) {
        super(engine);
    }

    @Override
    public void setupDatabase(DatabaseSetupRequest request) throws Exception {

        engine.setSubsystemEnabled(TKSAuthority.ID, true);

        super.setupDatabase(request);
    }

    @Override
    public void getDatabaseGroups(Collection<String> groups) throws Exception {
        groups.add("Token Key Service Manager Agents");
    }
}
