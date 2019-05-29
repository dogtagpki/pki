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
package org.dogtagpki.server.ocsp;

import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.Configurator;

public class OCSPConfigurator extends Configurator {

    private static final int DEF_REFRESH_IN_SECS_FOR_CLONE = 14400; // CRL Publishing schedule

    public void configureCloneRefresh(ConfigurationRequest request) {
        //Set well know default value for OCSP clone
        cs.putInteger("ocsp.store.defStore.refreshInSec", DEF_REFRESH_IN_SECS_FOR_CLONE);
    }
}
