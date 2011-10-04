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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.admin.certsrv.config.install;

import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * Display the SSL certificate request result
 *
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WISSLRequestResultPage extends WIRequestResultPage {

    WISSLRequestResultPage(JDialog parent) {
        super(parent);
    }

    WISSLRequestResultPage(JDialog parent, JFrame adminFrame) {
        super( parent, adminFrame);
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning())
            return false;
        if (wizardInfo.isSSLCertLocalCA() || wizardInfo.isMigrationEnable() ||
			wizardInfo.isSSLLocalCertDone()||
			(wizardInfo.isSSLCertRequestSucc() && wizardInfo.isSSLReqResultDisplayed()) ||
			wizardInfo.isSSLCertInstalledDone())
            return false;

		wizardInfo.setSSLReqResultDisplayed(Constants.TRUE);
        return super.initializePanel(info);
    }
}

