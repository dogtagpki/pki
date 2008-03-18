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

import com.netscape.admin.certsrv.wizard.*;
import javax.swing.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;

/**
 * The panel displays the certificate which will be installed in the token.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIDisplayOCSPCertPage extends WIDisplayCertPage {
    private static final String PANELNAME = "INSTALLDISPLAYOCSPCERTWIZARD";
    private static final String OCSPHELPINDEX = "install-ocspcert-display-wizard-help";
    
    WIDisplayOCSPCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIDisplayOCSPCertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isOCSPCloningDone())
            return false;

        if (wizardInfo.isOCSPCertLocalCA() || !wizardInfo.isInstallCertNow() ||
          !wizardInfo.isOCSPInstalled() || wizardInfo.isOCSPCertInstalledDone())
            return false;

            mHelpIndex = OCSPHELPINDEX;
        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        if (super.concludePanel(info)) {
            InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
            wizardInfo.put(ConfigConstants.STAGE_OCSP_CERT_REQUEST,
              ConfigConstants.TRUE);
            return true;
        }
    
        return false;
    }
}

