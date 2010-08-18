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
 * Setup key information for ssl server certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIServerKeyPage extends WIKeyPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLSERVERKEYWIZARD";
    private static final String LOCALHELPINDEX = 
      "install-serverkeylocal-configuration-wizard-help";
    private static final String REMOTEHELPINDEX = 
      "install-serverkeysub-configuration-wizard-help";

    WIServerKeyPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIServerKeyPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;

        if (mWizardInfo.isCloning())
            return false;

        if (mWizardInfo.isMigrationEnable() || mWizardInfo.isSSLLocalCertDone() ||
          mWizardInfo.isSSLCertRequestDone() || mWizardInfo.isSSLCertInstalledDone())
            return false;
        if (super.initializePanel(info)) {
            String sslTokenName = mWizardInfo.getSSLTokenName();
            if (sslTokenName == null || sslTokenName.equals("")) {
                mTokenBox.setSelectedIndex(0);
            } else {
                if (sslTokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
                    mTokenBox.setSelectedIndex(0);
                else
                    mTokenBox.setSelectedItem(sslTokenName);
            }
        }

        if (mWizardInfo.isSSLCertLocalCA())
            mHelpIndex = LOCALHELPINDEX;
        else 
            mHelpIndex = REMOTEHELPINDEX;

        enableFields();
        mIsCAKey = false;
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
        super.getUpdateInfo(info);
        mWizardInfo.setSSLTokenName(mWizardInfo.getTokenName());
    }
}

