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

import javax.swing.JDialog;
import javax.swing.JFrame;

import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;

/**
 * KRA Certificate Submission.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKRACertSubmitPage extends WICertSubmitPage {
    private static final String PANELNAME = "INSTALLKRACERTWIZARD";
    private static final String KRAHELPINDEX = "install-kratype-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakratype-wizard-help";

    WIKRACertSubmitPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isKRACloningDone())
            return false;
        wizardInfo.put(Constants.PR_CERTIFICATE_TYPE,
          Constants.PR_KRA_TRANSPORT_CERT);
        if (!wizardInfo.isKRAInstalled() ||
          wizardInfo.isKRACertRequestDone() || wizardInfo.isKRACertInstalledDone() ||
          !wizardInfo.isCAInstalled()) {
            wizardInfo.setKRACertLocalCA(Constants.FALSE);
            return false;
        }

        if (wizardInfo.isKRALocalCertDone())
            return false;

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = KRAHELPINDEX;
        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;

        return super.initializePanel(info);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mSelfButton.isSelected())
            wizardInfo.setKRACertLocalCA(Constants.TRUE);
        else
            wizardInfo.setKRACertLocalCA(Constants.FALSE);
    }
}
