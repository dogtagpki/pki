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
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.admin.certsrv.config.*;

/**
 * Setup key information for KRA transport certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKRAKeyPage extends WIKeyPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLKRAKEYWIZARD";
    private static final String KRAHELPINDEX =
      "install-krakeysub-configuration-wizard-help";
    private static final String CAKRALOCALHELPINDEX =
      "install-cakra-krakeylocal-configuration-wizard-help";
    private static final String CAKRAREMOTEHELPINDEX =
      "install-cakra-krakeysub-configuration-wizard-help";
    private static final String RAKRAHELPINDEX =
      "install-rakra-krakeysub-configuration-wizard-help";

    WIKRAKeyPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIKRAKeyPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;
        if (mWizardInfo.isCloning() && mWizardInfo.isKRACloningDone())
            return false;
        if (!mWizardInfo.isKRAInstalled() || mWizardInfo.isKRALocalCertDone() ||
          mWizardInfo.isKRACertRequestDone() || mWizardInfo.isKRACertInstalledDone())
            return false;
        if (super.initializePanel(info)) {
            String kraTokenName = mWizardInfo.getKRATokenName();
            if (kraTokenName == null || kraTokenName.equals("")) {
                mTokenBox.setSelectedIndex(0);
            } else {
                if (kraTokenName.equals(CryptoUtil.INTERNAL_TOKEN_NAME))
                    mTokenBox.setSelectedIndex(0);
                else
                    mTokenBox.setSelectedItem(kraTokenName);
            }
        }

        if (mWizardInfo.isCAInstalled() && mWizardInfo.isKRAInstalled()) {
            if (mWizardInfo.isKRACertLocalCA())
                mHelpIndex = CAKRALOCALHELPINDEX;
            else
                mHelpIndex = CAKRAREMOTEHELPINDEX;
        } else if (mWizardInfo.isRAInstalled() && mWizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = KRAHELPINDEX;

        enableFields();
        mIsCAKey = false;
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
        super.getUpdateInfo(info);
        mWizardInfo.setKRATokenName(mWizardInfo.getTokenName());
    }
}

