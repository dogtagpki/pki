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

/**
 * The panel displays the certificate which will be installed in the token.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIDisplayRACertPage extends WIDisplayCertPage {
    private static final String PANELNAME = "INSTALLDISPLAYRACERTWIZARD";
    private static final String RAHELPINDEX = "install-racert-display-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakracert-display-wizard-help";

    WIDisplayRACertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIDisplayRACertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isRACloningDone())
            return false;
        if (wizardInfo.isRACertLocalCA() || !wizardInfo.isInstallCertNow() ||
          !wizardInfo.isRAInstalled() || wizardInfo.isRACertInstalledDone())
            return false;

        if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = RAHELPINDEX;
        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        if (super.concludePanel(info)) {
            InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
            wizardInfo.put(ConfigConstants.STAGE_RA_CERT_REQUEST,
              ConfigConstants.TRUE);
            return true;
        }

        return false;
    }
}

