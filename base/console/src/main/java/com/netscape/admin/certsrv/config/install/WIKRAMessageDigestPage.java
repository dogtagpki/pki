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
import com.netscape.admin.certsrv.config.*;

/**
 * Setup the message digest information for the installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKRAMessageDigestPage extends WMessageDigestPage {

    private static final String PANELNAME = "INSTALLKRAMESSAGEDIGESTWIZARD";

    WIKRAMessageDigestPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIKRAMessageDigestPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isKRACloningDone())
            return false;
        if (!wizardInfo.isKRAInstalled() || !wizardInfo.isKRACertLocalCA() ||
          wizardInfo.isKRALocalCertDone() || wizardInfo.isKRACertRequestDone() ||
          wizardInfo.isKRACertInstalledDone())
            return false;

        mCAKeyType = wizardInfo.getCAKeyType();

        return super.initializePanel(info);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mDSAHashTypeBox.isVisible())
            wizardInfo.setHashType((String)mDSAHashTypeBox.getSelectedItem());
        else
            wizardInfo.setHashType((String)mRSAHashTypeBox.getSelectedItem());
    }
}
