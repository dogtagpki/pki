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
 * Setup key information for CA signing certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICAKeyPage extends WIKeyPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLCAKEYWIZARD";
    private static final String CALOCALHELPINDEX =
      "install-cakeylocal-configuration-wizard-help";
    private static final String CAREMOTEHELPINDEX =
      "install-cakeysub-configuration-wizard-help";
    private static final String CAKRALOCALHELPINDEX =
      "install-cakrakeylocal-configuration-wizard-help";
    private static final String CAKRAREMOTEHELPINDEX =
      "install-cakrakeysub-configuration-wizard-help";

    WICAKeyPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WICAKeyPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;
        if (mWizardInfo.isCloning() && mWizardInfo.isCACloningDone())
            return false;

        if (!mWizardInfo.isCAInstalled() || mWizardInfo.isMigrationEnable() ||
          mWizardInfo.isSelfSignedCACertDone() || mWizardInfo.isCACertRequestDone() ||
          mWizardInfo.isCACertInstalledDone())
            return false;

        if (super.initializePanel(info)) {
            String caTokenName = mWizardInfo.getCATokenName();
            if (caTokenName == null || caTokenName.equals("")) {
                mTokenBox.setSelectedIndex(0);
            } else {
                if (caTokenName.equals(CryptoUtil.INTERNAL_TOKEN_NAME))
                    mTokenBox.setSelectedIndex(0);
                else
                    mTokenBox.setSelectedItem(caTokenName);
            }
        }

        int counts = mKeyTypeBox.getItemCount();
        if (counts == 1)
            mKeyTypeBox.addItem("DSA");

        if (mWizardInfo.isCAInstalled() && mWizardInfo.isKRAInstalled()) {
            if (mWizardInfo.isCACertLocalCA())
                mHelpIndex = CAKRALOCALHELPINDEX;
            else
                mHelpIndex = CAKRAREMOTEHELPINDEX;
        } else if (mWizardInfo.isCACertLocalCA())
            mHelpIndex = CALOCALHELPINDEX;
        else
            mHelpIndex = CAREMOTEHELPINDEX;

        enableFields();
        mIsCAKey = true;
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
        super.getUpdateInfo(info);
        mWizardInfo.setCATokenName(mWizardInfo.getTokenName());

        if (mPassword.isEditable()) {
            String tokenname = mWizardInfo.getCATokenName();

            // this is used for single signon. The key is the token name with
            // the prefix "TOKEN:" and the value is the token password.
            mWizardInfo.put("TOKEN:"+tokenname, mPassword.getText().trim());
        }
    }
}

