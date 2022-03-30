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
 * OCSP Certificate Submission.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
class WIOCSPCertSubmitPage extends WICertSubmitPage {
    private static final String PANELNAME = "INSTALLOCSPCERTWIZARD";
    private static final String OCSPHELPINDEX = "install-ocsptype-wizard-help";

    WIOCSPCertSubmitPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isOCSPCloningDone())
            return false;
        wizardInfo.put(Constants.PR_CERTIFICATE_TYPE,
					   Constants.PR_OCSP_SIGNING_CERT);

        if (!wizardInfo.isOCSPInstalled() ||
          wizardInfo.isOCSPCertRequestDone() || wizardInfo.isOCSPCertInstalledDone()
 ||
          !wizardInfo.isCAInstalled()) {
            wizardInfo.setOCSPCertLocalCA(Constants.FALSE);
            return false;
        }
        if (wizardInfo.isOCSPLocalCertDone())
            return false;

        mHelpIndex = OCSPHELPINDEX;
        return super.initializePanel(info);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mSelfButton.isSelected())
            wizardInfo.setOCSPCertLocalCA(Constants.TRUE);
        else
            wizardInfo.setOCSPCertLocalCA(Constants.FALSE);
    }
}

