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
import java.awt.event.*;
import javax.swing.border.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;

/**
 * Certificate Extension page for CA signing Certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICACertExtensionPage extends WICertExtensionPage {
    private static final String PANELNAME = "INSTALLCACERTEXTENSION1WIZARD";
    private static final String CAHELPINDEX = "install-cacert-extension-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakracert-extension-wizard-help";

    WICACertExtensionPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WICACertExtensionPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isCACloningDone())
            return false;

        if (!wizardInfo.isCAInstalled() || wizardInfo.isMigrationEnable() ||
           wizardInfo.isSelfSignedCACertDone() ||
          wizardInfo.isCACertRequestDone() || wizardInfo.isCACertInstalledDone())
            return false;

        if (!mModified) {
            mBasicCheckBox.setSelected(true);
            mAKICheckBox.setSelected(true);
            mCACheckBox.setSelected(true);
            mSKICheckBox.setSelected(true);
            mCertPathBox.setSelected(false);
            mExtendedKeyCheckBox.setSelected(false);
            mKeyUsageBox.setSelected(true);
        }

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else
            mHelpIndex = CAHELPINDEX;

        return super.initializePanel(info);
    }
}
