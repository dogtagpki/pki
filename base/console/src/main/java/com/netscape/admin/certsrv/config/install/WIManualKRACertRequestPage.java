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
import com.netscape.certsrv.common.ConfigConstants;

/**
 * Generate the CA signing certificate request
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
class WIManualKRACertRequestPage extends WIManualCertRequestPage {
    private static final String PANELNAME = "INSTALLMANUALKRACERTREQUESTWIZARD";
    private static final String KRAHELPINDEX = "install-kracertrequest-manual-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakra-kracertrequest-manual-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakra-kracertrequest-manual-wizard-help";

    WIManualKRACertRequestPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIManualKRACertRequestPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isKRACloningDone())
            return false;
        if (wizardInfo.isKRACertLocalCA() || !wizardInfo.isKRAInstalled() ||
			wizardInfo.isKRALocalCertDone() ||
			wizardInfo.isKRACertInstalledDone() ||
			wizardInfo.isKRACertRequestSucc())
            return false;

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = KRAHELPINDEX;

        return super.initializePanel(info);
    }

    @Override
    public void back_cb(WizardInfo info) {
		super.back_cb(info);
		info.put(ConfigConstants.KRA_CERT_REQUEST_BACK,ConfigConstants.TRUE);
		info.put(ConfigConstants.KRA_REQUEST_DISPLAYED,ConfigConstants.FALSE);
    }
}

