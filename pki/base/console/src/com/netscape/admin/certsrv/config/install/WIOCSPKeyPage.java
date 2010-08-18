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
import com.netscape.management.client.util.*;

/**
 * Setup key information for RA signing certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIOCSPKeyPage extends WIKeyPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLOCSPKEYWIZARD";
    private static final String OCSPHELPINDEX = 
      "install-ocspkey-configuration-wizard-help";

    WIOCSPKeyPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIOCSPKeyPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;

        if (mWizardInfo.isCloning() && mWizardInfo.isOCSPCloningDone())
            return false;
        if (!mWizardInfo.isOCSPInstalled() || mWizardInfo.isOCSPLocalCertDone() ||
          mWizardInfo.isOCSPCertRequestDone() || mWizardInfo.isOCSPCertInstalledDone())
            return false;

        if (super.initializePanel(info)) {
            String ocspTokenName = mWizardInfo.getOCSPTokenName();
            if (ocspTokenName == null || ocspTokenName.equals("")) {
                mTokenBox.setSelectedIndex(0);
            } else {
                if (ocspTokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
                    mTokenBox.setSelectedIndex(0);
                else
                    mTokenBox.setSelectedItem(ocspTokenName);
            }
        }

        mHelpIndex = OCSPHELPINDEX;

        enableFields();
        mIsCAKey = false;
        mWizardInfo.setCertType(Constants.PR_OCSP_SIGNING_CERT);
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
        super.getUpdateInfo(info);
        mWizardInfo.setOCSPTokenName(mWizardInfo.getTokenName());
    }
}

