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
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * RA Certificate Submission.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIRACertSubmitPage extends WICertSubmitPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLRACERTWIZARD";
    private static final String RAHELPINDEX = "install-ratype-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakratype-wizard-help";

    WIRACertSubmitPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isRACloningDone())
            return false;
        wizardInfo.put(Constants.PR_CERTIFICATE_TYPE,
          Constants.PR_RA_SIGNING_CERT);
        if (!wizardInfo.isRAInstalled() ||
          wizardInfo.isRACertRequestDone() || wizardInfo.isRACertInstalledDone() ||
          !wizardInfo.isCAInstalled()) {
            wizardInfo.setRACertLocalCA(Constants.FALSE);
            return false;
        }
        if (wizardInfo.isRALocalCertDone())
            return false;
        if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = RAHELPINDEX;
        return super.initializePanel(info);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mSelfButton.isSelected())
            wizardInfo.setRACertLocalCA(Constants.TRUE);
        else
            wizardInfo.setRACertLocalCA(Constants.FALSE);
    }
}
