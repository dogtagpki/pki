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
import com.netscape.admin.certsrv.config.*;

/**
 * Setup key information for RA signing certificate
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIRAKeyPage extends WIKeyPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLRAKEYWIZARD";
    private static final String RAHELPINDEX = 
      "install-rakey-configuration-wizard-help";
    private static final String RAKRAHELPINDEX = 
      "install-rakrakey-configuration-wizard-help";

    WIRAKeyPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIRAKeyPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;

        if (mWizardInfo.isCloning() && mWizardInfo.isRACloningDone())
            return false;

        if (!mWizardInfo.isRAInstalled() || mWizardInfo.isRALocalCertDone() ||
          mWizardInfo.isRACertRequestDone() || mWizardInfo.isRACertInstalledDone())
            return false;

        if (super.initializePanel(info)) {
            String raTokenName = mWizardInfo.getRATokenName();
            if (raTokenName == null || raTokenName.equals("")) {
                mTokenBox.setSelectedIndex(0);
            } else {
                if (raTokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
                    mTokenBox.setSelectedIndex(0);
                else
                    mTokenBox.setSelectedItem(raTokenName);
            }
        }

        if (mWizardInfo.isRAInstalled() && mWizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = RAHELPINDEX;

        enableFields();
        mIsCAKey = false;
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
        super.getUpdateInfo(info);
        mWizardInfo.setRATokenName(mWizardInfo.getTokenName());
    }
}

