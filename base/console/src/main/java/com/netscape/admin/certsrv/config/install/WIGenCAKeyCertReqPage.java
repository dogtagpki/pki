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
import com.netscape.certsrv.common.Constants;

/**
 * Generate the CA signing certificate request
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
class WIGenCAKeyCertReqPage extends WIGenKeyCertReqPage {
    private static final String PANELNAME = "INSTALLGENCACERTREQWIZARD";
    private static final String CAHELPINDEX = "install-cacert-request-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakracert-request-wizard-help";

    WIGenCAKeyCertReqPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIGenCAKeyCertReqPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isCACloningDone())
            return false;

        if (wizardInfo.isCACertLocalCA() || !wizardInfo.isCAInstalled() ||
          wizardInfo.isMigrationEnable() || wizardInfo.isSelfSignedCACertDone()
          || (wizardInfo.isCACertRequestDone() &&
			  !wizardInfo.isCACertRequestBack()) ||
		  wizardInfo.isCACertInstalledDone())
            return false;

		if (wizardInfo.isCACertRequestBack()) {
			wizardInfo.put(ConfigConstants.STAGE_CA_CERT_REQUEST,
						   ConfigConstants.FALSE);
			wizardInfo.put(ConfigConstants.CA_CERT_REQUEST_BACK,
						   ConfigConstants.FALSE);
		}

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else
            mHelpIndex = CAHELPINDEX;

        mTokenName = wizardInfo.getCATokenName();
        wizardInfo.setCertType(Constants.PR_CA_SIGNING_CERT);
		wizardInfo.setNewRequest();
        return super.initializePanel(info);
    }
}

