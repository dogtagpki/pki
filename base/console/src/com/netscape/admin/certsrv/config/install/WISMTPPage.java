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

/**
 * SMTP page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WISMTPPage extends WizardBasePanel implements IWizardPanel {
    private JTextField mServerTxt, mPortTxt;
    private static final String PANELNAME = "SMTPWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WISMTPPage() {
        super(PANELNAME);
        init();
    }

    public boolean initializePanel(WizardInfo info) {
        return true;
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel headingLbl = makeJLabel("HEADING");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        add(headingLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel serverLbl = makeJLabel("SERVERNAME");
        gbc.anchor = gbc.NORTHEAST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.fill = gbc.NONE;
        add(serverLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mServerTxt = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        add(mServerTxt, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy2 = new JLabel("    ");
        gbc.anchor = gbc.NORTHEAST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel portLbl = makeJLabel("PORT");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        add(portLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPortTxt = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        add(mPortTxt, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy3 = new JLabel("     ");
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy3, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
