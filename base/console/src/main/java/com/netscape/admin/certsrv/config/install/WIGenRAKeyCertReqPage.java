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

import javax.swing.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * Generate the RA signing certificate request
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIGenRAKeyCertReqPage extends WIGenKeyCertReqPage {
    private static final String PANELNAME = "INSTALLGENRACERTREQWIZARD";
    private static final String RAHELPINDEX = "install-racert-request-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakracert-request-wizard-help";

    WIGenRAKeyCertReqPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIGenRAKeyCertReqPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isRACloningDone())
            return false;
        if (wizardInfo.isRACertLocalCA() || !wizardInfo.isRAInstalled() ||
          (wizardInfo.isRACertRequestDone() &&
			  !wizardInfo.isRACertRequestBack()) ||
          wizardInfo.isRALocalCertDone() ||
          wizardInfo.isRACertInstalledDone())
            return false;

		if (wizardInfo.isRACertRequestBack()) {
			wizardInfo.put(ConfigConstants.STAGE_RA_CERT_REQUEST,
						   ConfigConstants.FALSE);
			wizardInfo.put(ConfigConstants.RA_CERT_REQUEST_BACK,
						   ConfigConstants.FALSE);
		}

        if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = RAHELPINDEX;

        mTokenName = wizardInfo.getRATokenName();
        wizardInfo.setCertType(Constants.PR_RA_SIGNING_CERT);
		wizardInfo.setNewRequest();
        return super.initializePanel(info);
    }
}

