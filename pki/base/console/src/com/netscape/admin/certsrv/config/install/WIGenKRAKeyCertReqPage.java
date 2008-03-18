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
 * Generate the KRA signing certificate request
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIGenKRAKeyCertReqPage extends WIGenKeyCertReqPage {
    private static final String PANELNAME = "INSTALLGENKRACERTREQWIZARD";
    private static final String KRAHELPINDEX = "install-kracert-request-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakra-kracert-request-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakra-kracert-request-wizard-help";

    WIGenKRAKeyCertReqPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIGenKRAKeyCertReqPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isKRACloningDone())
            return false;
        if (wizardInfo.isKRACertLocalCA() || !wizardInfo.isKRAInstalled() ||
          (wizardInfo.isKRACertRequestDone() &&
			  !wizardInfo.isKRACertRequestBack()) || 
          wizardInfo.isKRALocalCertDone() ||
          wizardInfo.isKRACertInstalledDone())
            return false;

		if (wizardInfo.isCACertRequestBack()) {
			wizardInfo.put(ConfigConstants.STAGE_KRA_CERT_REQUEST,
						   ConfigConstants.FALSE);
			wizardInfo.put(ConfigConstants.KRA_CERT_REQUEST_BACK,
						   ConfigConstants.FALSE);
		}

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = KRAHELPINDEX;

        mTokenName = wizardInfo.getKRATokenName();
        wizardInfo.setCertType(Constants.PR_KRA_TRANSPORT_CERT);
		wizardInfo.setNewRequest();
        return super.initializePanel(info);
    }
}

