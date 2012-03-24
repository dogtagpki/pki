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
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;

/**
 * Validity page for CA signing certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICACertValidityPage extends WICertValidityPage {
    private static final String PANELNAME = "INSTALLCACERTVALIDWIZARD";
    private static final String CAHELPINDEX = "install-cacert-validity-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakracert-validity-wizard-help";
   
    WICACertValidityPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WICACertValidityPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isCACloningDone())
            return false;
        if (!wizardInfo.isCAInstalled() || wizardInfo.isMigrationEnable() ||
          wizardInfo.isSelfSignedCACertDone() || wizardInfo.isCACertRequestDone() ||
          wizardInfo.isCACertInstalledDone())
            return false;
        if (super.initializePanel(info)) {
            if (!wizardInfo.isCACertLocalCA())
                return false;

            if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
                mHelpIndex = CAKRAHELPINDEX;
            else
                mHelpIndex = CAHELPINDEX;

            return true;
        }
        return false;
    }
}

