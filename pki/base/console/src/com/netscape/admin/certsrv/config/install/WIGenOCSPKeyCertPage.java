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
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;

/**
 * Generate the OCSP signing certificate
 * 
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.keycert
 */
class WIGenOCSPKeyCertPage extends WIGenKeyCertPage {
    private static final String PANELNAME = "INSTALLGENOCSPWIZARD";
    private static final String OCSPHELPINDEX = "install-ocspcert-creation-wizard-help";

    WIGenOCSPKeyCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIGenOCSPKeyCertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

Debug.println("+++++++++++++++++++++++++++++=WIGenOCSPKeyCertPage ");
        if (!wizardInfo.isOCSPInstalled()) 
            return false;

        mHelpIndex = OCSPHELPINDEX;

        return super.initializePanel(info);
    }
}

