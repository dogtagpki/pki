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
 * Certificate Extension page for RA signing Certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIRACertExtensionPage extends WICertExtensionPage {
    private static final String PANELNAME = "INSTALLRACERTEXTENSION1WIZARD";
    private static final String RAHELPINDEX = "install-racert-extension-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakracert-extension-wizard-help";

    WIRACertExtensionPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIRACertExtensionPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isRACloningDone())
            return false;
        if (!wizardInfo.isRAInstalled() ||
          wizardInfo.isRALocalCertDone() || wizardInfo.isRACertRequestDone() ||
          wizardInfo.isRACertInstalledDone())
            return false;

        if (!mModified) {
            mAKICheckBox.setSelected(true);
            mExtendedKeyCheckBox.setSelected(true);
            mSSLClient.setSelected(true);
        }

        if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = RAHELPINDEX;

        return super.initializePanel(info);
    }
}
